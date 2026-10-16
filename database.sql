-- Слепок схемы PostgreSQL для Nyxo (итоговая схема после ворот G4).
--
-- ИСТОЧНИК ИСТИНЫ — initDatabase() в server.js вместе с lib/migrations/ и init*Schema в lib/:
-- они выполняются при каждом старте сервера, поэтому накатывать этот файл вручную не нужно.
-- Файл ГЕНЕРИРУЕТСЯ из свежей базы и руками не правится. Если он разошёлся с кодом, верен код.
--
-- Как получен (задача T5.1, 2026-10-16):
--   1. пустая база, сервер (node server.js, NODE_ENV=development, PostgreSQL 16) дошёл до GET /readyz;
--   2. pg_dump -s --no-owner --no-privileges <база>;
--   3. убраны служебные строки: \restrict и \unrestrict, SET параметров сессии, версии pg_dump.
-- Обновлять так же, а не править таблицы здесь.
--
-- Нужен PostgreSQL 13 или новее: nyxo_random_id и nyxo_random_seq_base используют gen_random_uuid().
-- Данных в файле нет. Строку schema_meta пишет сервер при старте; сброс старой схемы
-- (lib/legacy-reset.js) не срабатывает, пока таблица schema_meta существует. Версию схемы и
-- миграции после первого релиза ведёт lib/migrations (docs/dev/migrations.md).
-- Таблицы pow_used, rl_buckets и rl_counters — UNLOGGED: после аварии PostgreSQL они пустеют, это задумано.

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;

--
-- Name: nyxo_message_id_check(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.nyxo_message_id_check() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      IF EXISTS (SELECT 1 FROM message_tombstones WHERE id = NEW.id AND expires_at > now()) THEN
        RAISE EXCEPTION 'message id is retired' USING ERRCODE = '23505', CONSTRAINT = 'message_tombstones_pkey';
      END IF;
      RETURN NEW;
    END $$;

--
-- Name: nyxo_message_seq(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.nyxo_message_seq() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      IF NEW.room_id IS NOT NULL THEN
        UPDATE rooms SET msg_seq = msg_seq + 1 WHERE id = NEW.room_id RETURNING msg_seq INTO NEW.seq;
      ELSE
        UPDATE chats SET msg_seq = msg_seq + 1 WHERE id = NEW.chat_id RETURNING msg_seq INTO NEW.seq;
      END IF;
      IF NEW.seq IS NULL THEN
        RAISE EXCEPTION 'message scope not found' USING ERRCODE = '23503';
      END IF;
      RETURN NEW;
    END $$;

--
-- Name: nyxo_message_tombstone(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.nyxo_message_tombstone() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      INSERT INTO message_tombstones (id, expires_at)
      VALUES (OLD.id, date_trunc('day', now()) + interval '31 days')
      ON CONFLICT (id) DO UPDATE SET expires_at = GREATEST(message_tombstones.expires_at, EXCLUDED.expires_at);
      RETURN NULL;
    END $$;

--
-- Name: nyxo_random_id(regclass); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.nyxo_random_id(target regclass) RETURNS integer
    LANGUAGE plpgsql
    AS $_$
DECLARE
    candidate integer;
    taken boolean;
BEGIN
    LOOP
        candidate := (1000000 + ('x' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 12))::bit(48)::bigint % 2146483648)::integer;
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s WHERE id = $1)', target) INTO taken USING candidate;
        IF NOT taken THEN
            RETURN candidate;
        END IF;
    END LOOP;
END
$_$;

--
-- Name: nyxo_random_seq_base(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.nyxo_random_seq_base() RETURNS integer
    LANGUAGE sql
    AS $$
          SELECT (('x' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 8))::bit(32)::bigint % 1073741824)::integer
        $$;

--
-- Name: chat_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_settings (
    chat_id integer NOT NULL,
    default_message_expiry integer
);

--
-- Name: chats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chats (
    id integer DEFAULT public.nyxo_random_id('public.chats'::regclass) NOT NULL,
    user_id integer NOT NULL,
    room_id integer,
    name text NOT NULL,
    avatar text NOT NULL,
    online integer DEFAULT 0,
    is_bot integer DEFAULT 0,
    msg_seq integer DEFAULT public.nyxo_random_seq_base() NOT NULL,
    last_read_seq integer NOT NULL,
    created_at timestamp with time zone DEFAULT date_trunc('minute'::text, now()) NOT NULL,
    pinned boolean DEFAULT false NOT NULL,
    muted boolean DEFAULT false NOT NULL,
    archived boolean DEFAULT false NOT NULL
);

--
-- Name: e2ee_key_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.e2ee_key_requests (
    id integer NOT NULL,
    room_id integer NOT NULL,
    requester_id integer NOT NULL,
    key_id bytea NOT NULL,
    created_hour integer NOT NULL
);

--
-- Name: e2ee_key_requests_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.e2ee_key_requests_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: e2ee_key_requests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.e2ee_key_requests_id_seq OWNED BY public.e2ee_key_requests.id;

--
-- Name: e2ee_key_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.e2ee_key_shares (
    id integer NOT NULL,
    room_id integer NOT NULL,
    sender_id integer NOT NULL,
    recipient_id integer NOT NULL,
    ciphertext text NOT NULL
);

--
-- Name: e2ee_key_shares_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.e2ee_key_shares_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: e2ee_key_shares_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.e2ee_key_shares_id_seq OWNED BY public.e2ee_key_shares.id;

--
-- Name: identity_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_keys (
    user_id bigint NOT NULL,
    identity_signing_key bytea NOT NULL,
    identity_dh_key bytea NOT NULL,
    kt_nonce bytea,
    kt_gen integer,
    kt_epoch integer,
    kt_skt bytea
);

--
-- Name: join_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.join_requests (
    id integer DEFAULT public.nyxo_random_id('public.join_requests'::regclass) NOT NULL,
    room_id integer NOT NULL,
    user_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT date_trunc('minute'::text, now()) NOT NULL
);

--
-- Name: kt_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kt_entries (
    gen integer NOT NULL,
    epoch integer NOT NULL,
    label bytea NOT NULL,
    commitment bytea NOT NULL
);

--
-- Name: kt_epochs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kt_epochs (
    gen integer NOT NULL,
    epoch integer NOT NULL,
    smt_root bytea NOT NULL,
    head bytea NOT NULL,
    sig bytea NOT NULL,
    prev_final_head bytea
);

--
-- Name: kt_keychanges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kt_keychanges (
    old_pub bytea NOT NULL,
    new_pub bytea NOT NULL,
    gen integer NOT NULL,
    epoch integer NOT NULL,
    sig bytea NOT NULL,
    CONSTRAINT kt_keychanges_new_pub_check CHECK ((octet_length(new_pub) = 32)),
    CONSTRAINT kt_keychanges_old_pub_check CHECK ((octet_length(old_pub) = 32)),
    CONSTRAINT kt_keychanges_sig_check CHECK ((octet_length(sig) = 64))
);

--
-- Name: kt_nodes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kt_nodes (
    gen integer NOT NULL,
    epoch integer NOT NULL,
    depth smallint NOT NULL,
    prefix bytea NOT NULL,
    hash bytea NOT NULL,
    CONSTRAINT kt_nodes_depth_check CHECK (((depth >= 1) AND (depth <= 127))),
    CONSTRAINT kt_nodes_hash_check CHECK ((octet_length(hash) = 32))
);

--
-- Name: kt_pending; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kt_pending (
    commitment bytea NOT NULL,
    user_id integer NOT NULL,
    label bytea NOT NULL
);

--
-- Name: kt_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kt_state (
    singleton boolean DEFAULT true NOT NULL,
    gen integer NOT NULL,
    gen_start integer NOT NULL,
    open_epoch integer NOT NULL,
    last_head bytea NOT NULL,
    CONSTRAINT kt_state_singleton_check CHECK (singleton)
);

--
-- Name: message_expiry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_expiry (
    message_id integer NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    auto_delete_on_read boolean DEFAULT false
);

--
-- Name: message_tombstones; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_tombstones (
    id integer NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

--
-- Name: messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messages (
    id integer DEFAULT public.nyxo_random_id('public.messages'::regclass) NOT NULL,
    seq integer NOT NULL,
    chat_id integer,
    room_id integer,
    user_id integer,
    author_tag bytea,
    text text NOT NULL,
    file_url text,
    file_name text,
    file_type text,
    message_type text DEFAULT 'text'::text,
    sent integer DEFAULT 1,
    status text DEFAULT 'sent'::text,
    edited_at timestamp with time zone,
    reply_to_id integer,
    encrypted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT date_trunc('minute'::text, now()) NOT NULL,
    file_size bigint,
    CONSTRAINT messages_author_scope CHECK ((((room_id IS NULL) AND (chat_id IS NOT NULL) AND (user_id IS NOT NULL) AND (author_tag IS NULL)) OR ((room_id IS NOT NULL) AND (chat_id IS NULL) AND (user_id IS NULL) AND (author_tag IS NOT NULL) AND (octet_length(author_tag) = 16)))),
    CONSTRAINT messages_room_e2ee CHECK (((room_id IS NULL) OR encrypted))
);

--
-- Name: one_time_prekeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.one_time_prekeys (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    key_id bigint NOT NULL,
    public_key bytea NOT NULL
);

--
-- Name: one_time_prekeys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.one_time_prekeys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: one_time_prekeys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.one_time_prekeys_id_seq OWNED BY public.one_time_prekeys.id;

--
-- Name: pow_used; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.pow_used (
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

--
-- Name: pq_one_time_prekeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pq_one_time_prekeys (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    key_id bigint NOT NULL,
    public_key bytea NOT NULL,
    signature bytea NOT NULL
);

--
-- Name: pq_one_time_prekeys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.pq_one_time_prekeys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: pq_one_time_prekeys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.pq_one_time_prekeys_id_seq OWNED BY public.pq_one_time_prekeys.id;

--
-- Name: reactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reactions (
    id integer NOT NULL,
    message_id integer NOT NULL,
    user_id integer NOT NULL,
    emoji text NOT NULL
);

--
-- Name: reactions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.reactions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: reactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.reactions_id_seq OWNED BY public.reactions.id;

--
-- Name: rl_buckets; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.rl_buckets (
    k bytea NOT NULL,
    bucket timestamp with time zone NOT NULL,
    n integer NOT NULL
);

--
-- Name: rl_counters; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.rl_counters (
    k text NOT NULL,
    hits integer NOT NULL,
    reset_at timestamp with time zone NOT NULL
)
WITH (fillfactor='70');

--
-- Name: room_member_certs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.room_member_certs (
    room_id integer NOT NULL,
    subject_id integer NOT NULL,
    actor_id integer NOT NULL,
    kind smallint NOT NULL,
    cert bytea NOT NULL,
    aux bytea,
    snap bytea,
    CONSTRAINT room_member_certs_aux_check CHECK (((aux IS NULL) OR (octet_length(aux) = 335))),
    CONSTRAINT room_member_certs_cert_check CHECK ((octet_length(cert) = ANY (ARRAY[271, 335]))),
    CONSTRAINT room_member_certs_kind_check CHECK ((kind = ANY (ARRAY[1, 3, 4]))),
    CONSTRAINT room_member_certs_length CHECK ((octet_length(cert) =
CASE kind
    WHEN 3 THEN 335
    ELSE 271
END)),
    CONSTRAINT room_member_certs_snap_check CHECK (((snap IS NULL) OR (((octet_length(snap) % 16) = 0) AND (octet_length(snap) <= 16384))))
);

--
-- Name: room_participants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.room_participants (
    id integer NOT NULL,
    room_id integer NOT NULL,
    user_id integer NOT NULL,
    visible_from_seq integer NOT NULL
);

--
-- Name: room_participants_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.room_participants_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: room_participants_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.room_participants_id_seq OWNED BY public.room_participants.id;

--
-- Name: room_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.room_settings (
    room_id integer NOT NULL,
    default_message_expiry integer
);

--
-- Name: rooms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rooms (
    id integer DEFAULT public.nyxo_random_id('public.rooms'::regclass) NOT NULL,
    name text NOT NULL,
    code text NOT NULL,
    msg_seq integer DEFAULT public.nyxo_random_seq_base() NOT NULL,
    created_at timestamp with time zone DEFAULT date_trunc('minute'::text, now()) NOT NULL,
    code_expires_at timestamp with time zone,
    invite_max_members integer,
    invite_require_approval boolean DEFAULT true NOT NULL,
    invite_disabled boolean DEFAULT false NOT NULL,
    invite_cert bytea,
    invite_snap bytea,
    invite_actor_id integer,
    CONSTRAINT rooms_invite_cert_check CHECK (((invite_cert IS NULL) OR (octet_length(invite_cert) = 335))),
    CONSTRAINT rooms_invite_signed CHECK ((((invite_cert IS NULL) = (invite_snap IS NULL)) AND ((invite_cert IS NULL) = (invite_actor_id IS NULL)))),
    CONSTRAINT rooms_invite_snap_check CHECK (((invite_snap IS NULL) OR (((octet_length(invite_snap) % 16) = 0) AND (octet_length(invite_snap) <= 16384))))
);

--
-- Name: schema_meta; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_meta (
    singleton boolean DEFAULT true NOT NULL,
    schema_version integer NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT schema_meta_singleton_check CHECK (singleton)
);

--
-- Name: session; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.session (
    sid character varying NOT NULL,
    sess json NOT NULL,
    expire timestamp(6) without time zone NOT NULL
);

--
-- Name: signed_pq_prekeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.signed_pq_prekeys (
    user_id bigint NOT NULL,
    key_id bigint NOT NULL,
    public_key bytea NOT NULL,
    signature bytea NOT NULL
);

--
-- Name: signed_prekeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.signed_prekeys (
    user_id bigint NOT NULL,
    key_id bigint NOT NULL,
    public_key bytea NOT NULL,
    signature bytea NOT NULL
);

--
-- Name: upload_quota; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.upload_quota (
    qkey bytea NOT NULL,
    window_start date NOT NULL,
    bytes bigint NOT NULL,
    CONSTRAINT upload_quota_bytes_check CHECK ((bytes >= 0)),
    CONSTRAINT upload_quota_qkey_check CHECK ((octet_length(qkey) = 16))
);

--
-- Name: user_left_rooms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_left_rooms (
    user_id integer NOT NULL,
    room_id integer NOT NULL
);

--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer DEFAULT public.nyxo_random_id('public.users'::regclass) NOT NULL,
    unique_code text NOT NULL,
    username text NOT NULL,
    avatar text DEFAULT ''::text,
    created_at timestamp with time zone DEFAULT date_trunc('minute'::text, now()) NOT NULL,
    read_receipts boolean DEFAULT false NOT NULL,
    anon_lifetime text NOT NULL,
    last_active_at timestamp with time zone NOT NULL,
    CONSTRAINT users_anon_lifetime_check CHECK ((anon_lifetime = ANY (ARRAY['tab'::text, 'day'::text, 'week'::text])))
);

--
-- Name: e2ee_key_requests id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_requests ALTER COLUMN id SET DEFAULT nextval('public.e2ee_key_requests_id_seq'::regclass);

--
-- Name: e2ee_key_shares id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_shares ALTER COLUMN id SET DEFAULT nextval('public.e2ee_key_shares_id_seq'::regclass);

--
-- Name: one_time_prekeys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.one_time_prekeys ALTER COLUMN id SET DEFAULT nextval('public.one_time_prekeys_id_seq'::regclass);

--
-- Name: pq_one_time_prekeys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pq_one_time_prekeys ALTER COLUMN id SET DEFAULT nextval('public.pq_one_time_prekeys_id_seq'::regclass);

--
-- Name: reactions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reactions ALTER COLUMN id SET DEFAULT nextval('public.reactions_id_seq'::regclass);

--
-- Name: room_participants id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_participants ALTER COLUMN id SET DEFAULT nextval('public.room_participants_id_seq'::regclass);

--
-- Name: chat_settings chat_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_settings
    ADD CONSTRAINT chat_settings_pkey PRIMARY KEY (chat_id);

--
-- Name: chats chats_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chats
    ADD CONSTRAINT chats_pkey PRIMARY KEY (id);

--
-- Name: e2ee_key_requests e2ee_key_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_requests
    ADD CONSTRAINT e2ee_key_requests_pkey PRIMARY KEY (id);

--
-- Name: e2ee_key_requests e2ee_key_requests_room_id_requester_id_key_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_requests
    ADD CONSTRAINT e2ee_key_requests_room_id_requester_id_key_id_key UNIQUE (room_id, requester_id, key_id);

--
-- Name: e2ee_key_shares e2ee_key_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_shares
    ADD CONSTRAINT e2ee_key_shares_pkey PRIMARY KEY (id);

--
-- Name: identity_keys identity_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_keys
    ADD CONSTRAINT identity_keys_pkey PRIMARY KEY (user_id);

--
-- Name: join_requests join_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_requests
    ADD CONSTRAINT join_requests_pkey PRIMARY KEY (id);

--
-- Name: join_requests join_requests_room_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_requests
    ADD CONSTRAINT join_requests_room_id_user_id_key UNIQUE (room_id, user_id);

--
-- Name: kt_entries kt_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kt_entries
    ADD CONSTRAINT kt_entries_pkey PRIMARY KEY (gen, epoch, label, commitment);

--
-- Name: kt_epochs kt_epochs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kt_epochs
    ADD CONSTRAINT kt_epochs_pkey PRIMARY KEY (gen, epoch);

--
-- Name: kt_keychanges kt_keychanges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kt_keychanges
    ADD CONSTRAINT kt_keychanges_pkey PRIMARY KEY (old_pub);

--
-- Name: kt_nodes kt_nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kt_nodes
    ADD CONSTRAINT kt_nodes_pkey PRIMARY KEY (gen, epoch, depth, prefix);

--
-- Name: kt_pending kt_pending_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kt_pending
    ADD CONSTRAINT kt_pending_pkey PRIMARY KEY (commitment);

--
-- Name: kt_state kt_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kt_state
    ADD CONSTRAINT kt_state_pkey PRIMARY KEY (singleton);

--
-- Name: message_expiry message_expiry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_expiry
    ADD CONSTRAINT message_expiry_pkey PRIMARY KEY (message_id);

--
-- Name: message_tombstones message_tombstones_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_tombstones
    ADD CONSTRAINT message_tombstones_pkey PRIMARY KEY (id);

--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);

--
-- Name: one_time_prekeys one_time_prekeys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.one_time_prekeys
    ADD CONSTRAINT one_time_prekeys_pkey PRIMARY KEY (id);

--
-- Name: one_time_prekeys one_time_prekeys_user_id_key_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.one_time_prekeys
    ADD CONSTRAINT one_time_prekeys_user_id_key_id_key UNIQUE (user_id, key_id);

--
-- Name: pow_used pow_used_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pow_used
    ADD CONSTRAINT pow_used_pkey PRIMARY KEY (token_hash);

--
-- Name: pq_one_time_prekeys pq_one_time_prekeys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pq_one_time_prekeys
    ADD CONSTRAINT pq_one_time_prekeys_pkey PRIMARY KEY (id);

--
-- Name: pq_one_time_prekeys pq_one_time_prekeys_user_id_key_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pq_one_time_prekeys
    ADD CONSTRAINT pq_one_time_prekeys_user_id_key_id_key UNIQUE (user_id, key_id);

--
-- Name: reactions reactions_message_id_user_id_emoji_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reactions
    ADD CONSTRAINT reactions_message_id_user_id_emoji_key UNIQUE (message_id, user_id, emoji);

--
-- Name: reactions reactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reactions
    ADD CONSTRAINT reactions_pkey PRIMARY KEY (id);

--
-- Name: rl_buckets rl_buckets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rl_buckets
    ADD CONSTRAINT rl_buckets_pkey PRIMARY KEY (k, bucket);

--
-- Name: rl_counters rl_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rl_counters
    ADD CONSTRAINT rl_counters_pkey PRIMARY KEY (k);

--
-- Name: room_member_certs room_member_certs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_member_certs
    ADD CONSTRAINT room_member_certs_pkey PRIMARY KEY (room_id, subject_id, actor_id, kind);

--
-- Name: room_participants room_participants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_participants
    ADD CONSTRAINT room_participants_pkey PRIMARY KEY (id);

--
-- Name: room_participants room_participants_room_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_participants
    ADD CONSTRAINT room_participants_room_id_user_id_key UNIQUE (room_id, user_id);

--
-- Name: room_settings room_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_settings
    ADD CONSTRAINT room_settings_pkey PRIMARY KEY (room_id);

--
-- Name: rooms rooms_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rooms
    ADD CONSTRAINT rooms_code_key UNIQUE (code);

--
-- Name: rooms rooms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rooms
    ADD CONSTRAINT rooms_pkey PRIMARY KEY (id);

--
-- Name: schema_meta schema_meta_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_meta
    ADD CONSTRAINT schema_meta_pkey PRIMARY KEY (singleton);

--
-- Name: session session_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session
    ADD CONSTRAINT session_pkey PRIMARY KEY (sid);

--
-- Name: signed_pq_prekeys signed_pq_prekeys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signed_pq_prekeys
    ADD CONSTRAINT signed_pq_prekeys_pkey PRIMARY KEY (user_id);

--
-- Name: signed_prekeys signed_prekeys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signed_prekeys
    ADD CONSTRAINT signed_prekeys_pkey PRIMARY KEY (user_id);

--
-- Name: upload_quota upload_quota_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.upload_quota
    ADD CONSTRAINT upload_quota_pkey PRIMARY KEY (qkey);

--
-- Name: user_left_rooms user_left_rooms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_left_rooms
    ADD CONSTRAINT user_left_rooms_pkey PRIMARY KEY (user_id, room_id);

--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

--
-- Name: users users_unique_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_unique_code_key UNIQUE (unique_code);

--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);

--
-- Name: IDX_session_expire; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "IDX_session_expire" ON public.session USING btree (expire);

--
-- Name: idx_chats_archived; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chats_archived ON public.chats USING btree (room_id) WHERE archived;

--
-- Name: idx_chats_room_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chats_room_id ON public.chats USING btree (room_id);

--
-- Name: idx_chats_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chats_user_id ON public.chats USING btree (user_id);

--
-- Name: idx_e2ee_key_requests_hour; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_e2ee_key_requests_hour ON public.e2ee_key_requests USING btree (created_hour);

--
-- Name: idx_e2ee_key_shares_recipient; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_e2ee_key_shares_recipient ON public.e2ee_key_shares USING btree (recipient_id, room_id);

--
-- Name: idx_join_requests_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_join_requests_created ON public.join_requests USING btree (created_at);

--
-- Name: idx_join_requests_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_join_requests_user ON public.join_requests USING btree (user_id);

--
-- Name: idx_kt_entries_label; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kt_entries_label ON public.kt_entries USING btree (label, gen, epoch);

--
-- Name: idx_kt_pending_label; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kt_pending_label ON public.kt_pending USING btree (label);

--
-- Name: idx_kt_pending_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kt_pending_user ON public.kt_pending USING btree (user_id);

--
-- Name: idx_message_expiry_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_message_expiry_expires_at ON public.message_expiry USING btree (expires_at);

--
-- Name: idx_message_tombstones_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_message_tombstones_expires ON public.message_tombstones USING btree (expires_at);

--
-- Name: idx_messages_chat_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_chat_id ON public.messages USING btree (chat_id) WHERE (chat_id IS NOT NULL);

--
-- Name: idx_messages_chat_seq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_messages_chat_seq ON public.messages USING btree (chat_id, seq) INCLUDE (user_id, sent, encrypted) WHERE (room_id IS NULL);

--
-- Name: idx_messages_file_url; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_file_url ON public.messages USING btree (file_url) WHERE (file_url IS NOT NULL);

--
-- Name: idx_messages_reply_to_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_reply_to_id ON public.messages USING btree (reply_to_id) WHERE (reply_to_id IS NOT NULL);

--
-- Name: idx_messages_room_author; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_room_author ON public.messages USING btree (room_id, author_tag) WHERE (room_id IS NOT NULL);

--
-- Name: idx_messages_room_seq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_messages_room_seq ON public.messages USING btree (room_id, seq) INCLUDE (sent, encrypted) WHERE (room_id IS NOT NULL);

--
-- Name: idx_messages_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_user_id ON public.messages USING btree (user_id) WHERE (user_id IS NOT NULL);

--
-- Name: idx_otpk_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_otpk_user ON public.one_time_prekeys USING btree (user_id);

--
-- Name: idx_pqotpk_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pqotpk_user ON public.pq_one_time_prekeys USING btree (user_id, id);

--
-- Name: idx_reactions_msg_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reactions_msg_user ON public.reactions USING btree (message_id, user_id);

--
-- Name: idx_rmc_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rmc_actor ON public.room_member_certs USING btree (actor_id);

--
-- Name: idx_rmc_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rmc_subject ON public.room_member_certs USING btree (subject_id);

--
-- Name: idx_room_participants_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_room_participants_user ON public.room_participants USING btree (user_id);

--
-- Name: idx_session_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_session_user ON public.session USING btree (((sess ->> 'userId'::text)));

--
-- Name: idx_user_left_rooms_room; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_left_rooms_room ON public.user_left_rooms USING btree (room_id);

--
-- Name: idx_users_lifetime; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_lifetime ON public.users USING btree (anon_lifetime, last_active_at);

--
-- Name: messages messages_10_id_check; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER messages_10_id_check BEFORE INSERT ON public.messages FOR EACH ROW EXECUTE FUNCTION public.nyxo_message_id_check();

--
-- Name: messages messages_20_seq; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER messages_20_seq BEFORE INSERT ON public.messages FOR EACH ROW EXECUTE FUNCTION public.nyxo_message_seq();

--
-- Name: messages messages_90_tombstone; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER messages_90_tombstone AFTER DELETE ON public.messages FOR EACH ROW EXECUTE FUNCTION public.nyxo_message_tombstone();

--
-- Name: chat_settings chat_settings_chat_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_settings
    ADD CONSTRAINT chat_settings_chat_id_fkey FOREIGN KEY (chat_id) REFERENCES public.chats(id) ON DELETE CASCADE;

--
-- Name: chats chats_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chats
    ADD CONSTRAINT chats_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.rooms(id) ON DELETE CASCADE;

--
-- Name: chats chats_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chats
    ADD CONSTRAINT chats_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

--
-- Name: e2ee_key_requests e2ee_key_requests_requester_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_requests
    ADD CONSTRAINT e2ee_key_requests_requester_id_fkey FOREIGN KEY (requester_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: e2ee_key_requests e2ee_key_requests_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_requests
    ADD CONSTRAINT e2ee_key_requests_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.rooms(id) ON DELETE CASCADE;

--
-- Name: e2ee_key_shares e2ee_key_shares_recipient_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_shares
    ADD CONSTRAINT e2ee_key_shares_recipient_id_fkey FOREIGN KEY (recipient_id) REFERENCES public.users(id);

--
-- Name: e2ee_key_shares e2ee_key_shares_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_shares
    ADD CONSTRAINT e2ee_key_shares_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.rooms(id) ON DELETE CASCADE;

--
-- Name: e2ee_key_shares e2ee_key_shares_sender_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_shares
    ADD CONSTRAINT e2ee_key_shares_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.users(id);

--
-- Name: join_requests join_requests_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_requests
    ADD CONSTRAINT join_requests_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.rooms(id) ON DELETE CASCADE;

--
-- Name: join_requests join_requests_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_requests
    ADD CONSTRAINT join_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

--
-- Name: message_expiry message_expiry_message_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_expiry
    ADD CONSTRAINT message_expiry_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.messages(id) ON DELETE CASCADE;

--
-- Name: messages messages_chat_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_chat_id_fkey FOREIGN KEY (chat_id) REFERENCES public.chats(id) ON DELETE CASCADE;

--
-- Name: messages messages_reply_to_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_reply_to_id_fkey FOREIGN KEY (reply_to_id) REFERENCES public.messages(id) ON DELETE SET NULL;

--
-- Name: messages messages_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.rooms(id) ON DELETE CASCADE;

--
-- Name: messages messages_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

--
-- Name: reactions reactions_message_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reactions
    ADD CONSTRAINT reactions_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.messages(id) ON DELETE CASCADE;

--
-- Name: reactions reactions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reactions
    ADD CONSTRAINT reactions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

--
-- Name: room_member_certs room_member_certs_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_member_certs
    ADD CONSTRAINT room_member_certs_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.rooms(id) ON DELETE CASCADE;

--
-- Name: room_participants room_participants_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_participants
    ADD CONSTRAINT room_participants_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.rooms(id) ON DELETE CASCADE;

--
-- Name: room_participants room_participants_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_participants
    ADD CONSTRAINT room_participants_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

--
-- Name: room_settings room_settings_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_settings
    ADD CONSTRAINT room_settings_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.rooms(id) ON DELETE CASCADE;

--
-- Name: user_left_rooms user_left_rooms_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_left_rooms
    ADD CONSTRAINT user_left_rooms_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.rooms(id) ON DELETE CASCADE;

--
-- Name: user_left_rooms user_left_rooms_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_left_rooms
    ADD CONSTRAINT user_left_rooms_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

--
--
