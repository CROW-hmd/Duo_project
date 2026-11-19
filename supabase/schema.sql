-- عُطرٌ وَ شِعر | تشغيل مرة واحدة في SQL Editor لمشروع Supabase مخصص للمتجر.
-- الجداول محمية بـ RLS، الأسعار والمخزون تُفحص داخل دالة تنفيذ الطلب.
begin;
create extension if not exists pgcrypto;
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to anon, authenticated;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  role text not null default 'customer' check(role in ('customer','admin')),
  created_at timestamptz not null default now()
);

create or replace function private.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, full_name, role)
  values (new.id, left(coalesce(new.raw_user_meta_data ->> 'full_name', ''), 80), 'customer')
  on conflict (id) do nothing;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created_otr on auth.users;
create trigger on_auth_user_created_otr after insert on auth.users
for each row execute function private.handle_new_user();
revoke all on function private.handle_new_user() from public, anon, authenticated;

create or replace function private.is_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid()) and role = 'admin'
  );
$$;
revoke all on function private.is_admin() from public;
grant execute on function private.is_admin() to anon, authenticated;

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null check(char_length(name) between 2 and 100),
  description text not null check(char_length(description) between 5 and 1000),
  category text not null default 'شرقي' check(char_length(category) between 2 and 50),
  price_iqd integer not null check(price_iqd between 1000 and 100000000),
  stock integer not null default 0 check(stock between 0 and 100000),
  image_url text check(image_url is null or char_length(image_url) <= 2000),
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create index if not exists products_active_created_idx on public.products(active,created_at desc);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete restrict,
  customer_name text not null check(char_length(customer_name) between 2 and 90),
  phone text not null check(char_length(phone) between 7 and 22),
  address text not null check(char_length(address) between 10 and 400),
  notes text check(notes is null or char_length(notes) <= 500),
  payment_method text not null default 'cash_on_delivery' check(payment_method = 'cash_on_delivery'),
  status text not null default 'pending' check(status in ('pending','processing','delivered','cancelled')),
  total_iqd bigint not null check(total_iqd >= 0),
  created_at timestamptz not null default now()
);
create index if not exists orders_user_created_idx on public.orders(user_id,created_at desc);
create index if not exists orders_status_created_idx on public.orders(status,created_at desc);

create table if not exists public.order_items (
  id bigint generated always as identity primary key,
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid references public.products(id) on delete set null,
  product_name text not null,
  quantity integer not null check(quantity between 1 and 20),
  unit_price_iqd integer not null check(unit_price_iqd >= 1000)
);
create index if not exists order_items_order_idx on public.order_items(order_id);

alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;

create policy "profiles_read_self" on public.profiles for select to authenticated using(id = (select auth.uid()));
create policy "products_read_live_or_admin" on public.products for select to anon, authenticated using(active or (select private.is_admin()));
create policy "products_insert_admin" on public.products for insert to authenticated with check((select private.is_admin()));
create policy "products_update_admin" on public.products for update to authenticated using((select private.is_admin())) with check((select private.is_admin()));
create policy "products_delete_admin" on public.products for delete to authenticated using((select private.is_admin()));
create policy "orders_read_own_or_admin" on public.orders for select to authenticated using(user_id = (select auth.uid()) or (select private.is_admin()));
create policy "orders_update_admin" on public.orders for update to authenticated using((select private.is_admin())) with check((select private.is_admin()));
create policy "items_read_own_or_admin" on public.order_items for select to authenticated using(
  exists (select 1 from public.orders o where o.id = order_id and (o.user_id = (select auth.uid()) or (select private.is_admin())))
);

-- No INSERT permission for orders/order_items: checkout goes through place_order RPC only.
revoke all on public.profiles,public.products,public.orders,public.order_items from anon,authenticated;
grant select on public.products to anon,authenticated;
grant insert,update,delete on public.products to authenticated;
grant select on public.profiles to authenticated;
grant select on public.orders,public.order_items to authenticated;
grant update(status) on public.orders to authenticated;

-- Atomically price and reserve stock on the server. Never trust totals sent by browser.
create or replace function public.place_order(
  p_items jsonb,
  p_name text,
  p_phone text,
  p_address text,
  p_notes text default null
) returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_user uuid := auth.uid();
  v_count integer := 0;
  v_total bigint := 0;
  v_order uuid;
  r record;
begin
  if v_user is null then raise exception 'يرجى تسجيل الدخول أولاً'; end if;
  if p_name is null or char_length(trim(p_name)) not between 2 and 90 then raise exception 'الاسم غير صحيح'; end if;
  if p_phone is null or p_phone !~ '^[0-9+ ()-]{7,22}$' then raise exception 'رقم الهاتف غير صحيح'; end if;
  if p_address is null or char_length(trim(p_address)) not between 10 and 400 then raise exception 'يرجى إدخال عنوان واضح'; end if;
  if p_notes is not null and char_length(p_notes) > 500 then raise exception 'الملاحظات طويلة جدًا'; end if;
  if jsonb_typeof(p_items) is distinct from 'array' or jsonb_array_length(p_items) not between 1 and 40 then
    raise exception 'السلة غير صالحة';
  end if;
  if exists (
    select 1 from jsonb_array_elements(p_items) x
    where jsonb_typeof(x) <> 'object'
       or (x->>'quantity') !~ '^[0-9]{1,2}$'
       or (x->>'id') is null
  ) then raise exception 'بيانات العطور غير صالحة'; end if;

  -- The first pass locks inventory rows, so concurrent checkouts cannot oversell.
  for r in
    select p.id, p.name, p.price_iqd, p.stock, p.active, q.qty
    from (
      select (x->>'id')::uuid as id, sum((x->>'quantity')::integer)::integer as qty
      from jsonb_array_elements(p_items) x group by 1
    ) q
    join public.products p on p.id=q.id
    order by p.id
    for update of p
  loop
    if not r.active or r.qty not between 1 and 20 or r.stock < r.qty then
      raise exception 'أحد العطور غير متوفر بالكمية المطلوبة';
    end if;
    v_count := v_count + 1;
    v_total := v_total + (r.price_iqd::bigint * r.qty);
  end loop;
  if v_count <> (select count(distinct x->>'id') from jsonb_array_elements(p_items) x) then
    raise exception 'أحد العطور لم يعد متوفرًا';
  end if;

  insert into public.orders(user_id,customer_name,phone,address,notes,total_iqd)
  values(v_user,trim(p_name),trim(p_phone),trim(p_address),nullif(trim(coalesce(p_notes,'')),''),v_total)
  returning id into v_order;

  for r in
    select p.id,p.name,p.price_iqd,q.qty
    from (
      select (x->>'id')::uuid id, sum((x->>'quantity')::integer)::integer qty
      from jsonb_array_elements(p_items) x group by 1
    ) q join public.products p on p.id=q.id order by p.id
  loop
    insert into public.order_items(order_id,product_id,product_name,quantity,unit_price_iqd)
    values(v_order,r.id,r.name,r.qty,r.price_iqd);
    update public.products set stock=stock-r.qty where id=r.id;
  end loop;
  return v_order;
end;
$$;
revoke all on function public.place_order(jsonb,text,text,text,text) from public,anon;
grant execute on function public.place_order(jsonb,text,text,text,text) to authenticated;

-- Restock once when an admin cancels an order, and disallow reopening cancelled orders.
create or replace function private.on_order_status_change()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if old.status = 'cancelled' and new.status <> 'cancelled' then
    raise exception 'لا يمكن إعادة فتح طلب ملغي';
  end if;
  if old.status <> 'cancelled' and new.status = 'cancelled' then
    update public.products p set stock=p.stock+i.quantity
    from public.order_items i where i.order_id=old.id and i.product_id=p.id;
  end if;
  return new;
end;
$$;
drop trigger if exists restore_stock_when_cancelled_otr on public.orders;
create trigger restore_stock_when_cancelled_otr before update of status on public.orders
for each row execute function private.on_order_status_change();
revoke all on function private.on_order_status_change() from public,anon,authenticated;

-- Admin-only uploads; customer storefront may display these publicly hosted product photos.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values ('perfume-images','perfume-images',true,5242880,array['image/jpeg','image/png','image/webp'])
on conflict(id) do update set public=true,file_size_limit=5242880,allowed_mime_types=excluded.allowed_mime_types;
create policy "perfume_images_public_read" on storage.objects for select to anon,authenticated using(bucket_id='perfume-images');
create policy "perfume_images_admin_insert" on storage.objects for insert to authenticated with check(bucket_id='perfume-images' and (select private.is_admin()));
create policy "perfume_images_admin_update" on storage.objects for update to authenticated using(bucket_id='perfume-images' and (select private.is_admin())) with check(bucket_id='perfume-images' and (select private.is_admin()));
create policy "perfume_images_admin_delete" on storage.objects for delete to authenticated using(bucket_id='perfume-images' and (select private.is_admin()));
commit;

-- FIRST ADMIN (RUN SEPARATELY ONLY AFTER SIGNING UP WITH THE ADMIN EMAIL):
-- update public.profiles set role = 'admin'
-- where id = (select id from auth.users where email = 'YOUR-ADMIN-EMAIL@example.com');