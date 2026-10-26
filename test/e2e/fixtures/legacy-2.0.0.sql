--
-- PostgreSQL database dump
--


-- Dumped from database version 16.15
-- Dumped by pg_dump version 16.15

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

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


SET default_tablespace = '';

SET default_table_access_method = heap;

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
    last_read_message_id integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    pinned boolean DEFAULT false NOT NULL,
    muted boolean DEFAULT false NOT NULL,
    archived boolean DEFAULT false NOT NULL
);


--
-- Name: chats_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chats_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chats_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chats_id_seq OWNED BY public.chats.id;


--
-- Name: e2ee_key_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.e2ee_key_shares (
    id integer NOT NULL,
    room_id integer NOT NULL,
    sender_id integer NOT NULL,
    recipient_id integer NOT NULL,
    ciphertext text NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
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
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: join_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.join_requests (
    id integer DEFAULT public.nyxo_random_id('public.join_requests'::regclass) NOT NULL,
    room_id integer NOT NULL,
    user_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
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
-- Name: messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messages (
    id integer NOT NULL,
    chat_id integer,
    room_id integer,
    user_id integer NOT NULL,
    text text NOT NULL,
    file_url text,
    file_name text,
    file_type text,
    message_type text DEFAULT 'text'::text,
    sent integer DEFAULT 1,
    "time" text NOT NULL,
    status text DEFAULT 'sent'::text,
    edited_at text,
    deleted integer DEFAULT 0,
    reply_to_id integer,
    encrypted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    file_size bigint
);


--
-- Name: messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.messages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.messages_id_seq OWNED BY public.messages.id;


--
-- Name: one_time_prekeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.one_time_prekeys (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    key_id bigint NOT NULL,
    public_key bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
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
-- Name: room_participants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.room_participants (
    id integer NOT NULL,
    room_id integer NOT NULL,
    user_id integer NOT NULL,
    visible_from_id integer DEFAULT 0 NOT NULL
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
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    code_expires_at timestamp with time zone,
    invite_max_members integer,
    invite_require_approval boolean DEFAULT true NOT NULL,
    invite_disabled boolean DEFAULT false NOT NULL
);


--
-- Name: rooms_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.rooms_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: rooms_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.rooms_id_seq OWNED BY public.rooms.id;


--
-- Name: security_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_events (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    type text NOT NULL,
    client text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: security_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.security_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: security_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.security_events_id_seq OWNED BY public.security_events.id;


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
    signature bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: signed_prekeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.signed_prekeys (
    user_id bigint NOT NULL,
    key_id bigint NOT NULL,
    public_key bytea NOT NULL,
    signature bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: unread; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.unread (
    id integer NOT NULL,
    chat_id integer NOT NULL,
    user_id integer NOT NULL,
    count integer DEFAULT 0
);


--
-- Name: unread_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.unread_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: unread_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.unread_id_seq OWNED BY public.unread.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer DEFAULT public.nyxo_random_id('public.users'::regclass) NOT NULL,
    unique_code text NOT NULL,
    username text NOT NULL,
    email text,
    password text,
    avatar text DEFAULT ''::text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    read_receipts boolean DEFAULT true NOT NULL,
    anon_lifetime text,
    last_active_at timestamp with time zone
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: e2ee_key_shares id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.e2ee_key_shares ALTER COLUMN id SET DEFAULT nextval('public.e2ee_key_shares_id_seq'::regclass);


--
-- Name: messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages ALTER COLUMN id SET DEFAULT nextval('public.messages_id_seq'::regclass);


--
-- Name: one_time_prekeys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.one_time_prekeys ALTER COLUMN id SET DEFAULT nextval('public.one_time_prekeys_id_seq'::regclass);


--
-- Name: reactions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reactions ALTER COLUMN id SET DEFAULT nextval('public.reactions_id_seq'::regclass);


--
-- Name: room_participants id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_participants ALTER COLUMN id SET DEFAULT nextval('public.room_participants_id_seq'::regclass);


--
-- Name: security_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events ALTER COLUMN id SET DEFAULT nextval('public.security_events_id_seq'::regclass);


--
-- Name: unread id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unread ALTER COLUMN id SET DEFAULT nextval('public.unread_id_seq'::regclass);


--
-- Data for Name: chat_settings; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chats; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.chats (id, user_id, room_id, name, avatar, online, is_bot, last_read_message_id, created_at, pinned, muted, archived) VALUES (476638372, 369265884, NULL, 'Бот Помощник', 'Б', 1, 1, 0, '2026-09-28 21:15:51.651851+00', false, false, false);
INSERT INTO public.chats (id, user_id, room_id, name, avatar, online, is_bot, last_read_message_id, created_at, pinned, muted, archived) VALUES (251202473, 1955890954, NULL, 'Бот Помощник', 'Б', 1, 1, 0, '2026-09-28 21:15:52.152141+00', false, false, false);
INSERT INTO public.chats (id, user_id, room_id, name, avatar, online, is_bot, last_read_message_id, created_at, pinned, muted, archived) VALUES (1079503621, 1141387901, NULL, 'Бот Помощник', 'Б', 1, 1, 0, '2026-09-28 21:15:52.252407+00', false, false, false);
INSERT INTO public.chats (id, user_id, room_id, name, avatar, online, is_bot, last_read_message_id, created_at, pinned, muted, archived) VALUES (401576716, 369265884, 934210995, 'Команда', 'К', 0, 0, 0, '2026-09-28 21:15:52.766977+00', false, false, false);
INSERT INTO public.chats (id, user_id, room_id, name, avatar, online, is_bot, last_read_message_id, created_at, pinned, muted, archived) VALUES (846079934, 1955890954, 934210995, 'Чат с alice', 'Ч', 0, 0, 0, '2026-09-28 21:15:52.854708+00', false, false, false);
INSERT INTO public.chats (id, user_id, room_id, name, avatar, online, is_bot, last_read_message_id, created_at, pinned, muted, archived) VALUES (1580920077, 1141387901, 934210995, 'Чат с alice', 'Ч', 0, 0, 0, '2026-09-28 21:15:52.958204+00', false, false, false);
INSERT INTO public.chats (id, user_id, room_id, name, avatar, online, is_bot, last_read_message_id, created_at, pinned, muted, archived) VALUES (1425425823, 1955890954, 2101399303, 'Личное bob', 'Л', 0, 0, 0, '2026-09-28 21:15:53.120842+00', false, false, false);


--
-- Data for Name: e2ee_key_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: identity_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: join_requests; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: message_expiry; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: messages; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.messages (id, chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, "time", status, edited_at, deleted, reply_to_id, encrypted, created_at, file_size) VALUES (1, 476638372, NULL, 369265884, 'enc:v2:7e748ea9:mh2yxxYIXUILnH1r:RNeOWvwudVlXauK7p+GqCg==:/p0Oltu/SCkXGSDkfJctdFIiAvkQNduBjSbZbVz6WqAP3CWnGztOjLOOk2uAW8scP9GkRRtKjJJDikq6STb+vmyOSgLTkhU=', NULL, NULL, NULL, 'text', 0, '00:15', 'read', NULL, 0, NULL, false, '2026-09-28 21:15:51.651851+00', NULL);
INSERT INTO public.messages (id, chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, "time", status, edited_at, deleted, reply_to_id, encrypted, created_at, file_size) VALUES (2, 251202473, NULL, 1955890954, 'enc:v2:7e748ea9:kIV6a7H/rUSb+EZD:rKvKbhWKfApjP3R1SUNssg==:yep0JuGl83P5hzmbhIedoktR8CWJWWWGpuz5f0DHyvz6xBqZhldPO0eJVcDqG/8/gnRzucgQyj7EeqKXJqHxVks88yUw9Ls=', NULL, NULL, NULL, 'text', 0, '00:15', 'read', NULL, 0, NULL, false, '2026-09-28 21:15:52.152141+00', NULL);
INSERT INTO public.messages (id, chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, "time", status, edited_at, deleted, reply_to_id, encrypted, created_at, file_size) VALUES (3, 1079503621, NULL, 1141387901, 'enc:v2:7e748ea9:pSIrrcjRT0h7ykdy:mJnRk+dhTItBbKIogA/6eA==:/z9I2k3eaCo/2fCbsN/4vzI00JA30TpW0RByjzizSagpoigzau/lHtyHUACd0UORy61TsM7dnHWvVZwPhSqvPrWkVsqQN3tM2SvMMuD0eNf2DBsQCqZ6Y2U6RA99M00NJroOsPYY8hsoq8zzGAbVf2HRGL5sZiRb7WJKQ4P+42/GKbfh+K4lq2NK4jfDfHWxDMF1GpAW1cVmgMDem9T6ZaSImZqZ9fjk2luMrmzngl7P6aUM/vXStbqd0bpWGIvHxiMqAlhB5Igv9O/kKo4nxxf3dfeWXy1YVqCqMEyEbyxWnduIWwV2KIv1tPP63N0tYHUxBf3HYvlC+Nr0VET58UcijspjNmIYIyM4S37/XvY3wJoJjcM81siNd5uly4iwsZgOMRL5g1tQg19eVPWeYo90fs8VE6xs1qQVOG/l4wJ0650dLaue+6hjBJL3V3JH2fLL2rE9tVhGmjvbxz13GEQjBxDqkJGv048S8CjX68+Rj9xT9Zb7F0Tm/ctyT4joJhA73QjVsDvPksQKgw8Vd8/K1pF1uxiT8vWNdG3LFucc0mLAOQLKzwWOQT3WYHqPRFzfVoBtARi9UUQDUsUTxEcpgLVthN1sNIakYx0S4eIDGGv4JP1xSIHmWk09WI4K9ElnSqGeHapNLiUat9fRpEh887cMd8saj4nrioxXolWLxNa25g==', NULL, NULL, NULL, 'text', 0, '00:15', 'read', NULL, 0, NULL, false, '2026-09-28 21:15:52.252407+00', NULL);
INSERT INTO public.messages (id, chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, "time", status, edited_at, deleted, reply_to_id, encrypted, created_at, file_size) VALUES (4, 401576716, 934210995, 369265884, 'enc:v2:7e748ea9:j4Llpm1CblcOQScD:lz5iS0SfX6vaRYAyLAe2nQ==:Ch1/pLtilioAvBCSJ71DLCbgaKIp', NULL, NULL, NULL, 'text', 1, '00:15', 'sent', NULL, 0, NULL, false, '2026-09-28 21:15:53.017091+00', NULL);
INSERT INTO public.messages (id, chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, "time", status, edited_at, deleted, reply_to_id, encrypted, created_at, file_size) VALUES (5, 846079934, 934210995, 1955890954, 'enc:v2:7e748ea9:bk/oIq/h0RVeocZs:quzy01wejK16LvI/N8oxsg==:j76egxYC4dRGRmb5MUDtknOj3g==', NULL, NULL, NULL, 'text', 1, '00:15', 'sent', NULL, 0, NULL, false, '2026-09-28 21:15:53.086732+00', NULL);
INSERT INTO public.messages (id, chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, "time", status, edited_at, deleted, reply_to_id, encrypted, created_at, file_size) VALUES (6, 1580920077, 934210995, 1141387901, 'enc:v2:7e748ea9:NHuGditdUxnKBVNU:7dLO0yBsPSyUYUGuTlDxFg==:Uguf3wujRt4YnKoVWg==', NULL, NULL, NULL, 'text', 1, '00:15', 'sent', NULL, 0, NULL, false, '2026-09-28 21:15:53.100121+00', NULL);
INSERT INTO public.messages (id, chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, "time", status, edited_at, deleted, reply_to_id, encrypted, created_at, file_size) VALUES (7, 401576716, 934210995, 369265884, 'enc:v2:7e748ea9:f0/ShQqlFGmaA+wR:dpq5Ssb4rlf8yLT0PR+yyQ==:OPd2vyHr+l8G1l/5DfiKeN2aIFIolSNTsQU3IsvGJ4Z/FaFDOA==', NULL, NULL, NULL, 'text', 1, '00:15', 'sent', NULL, 0, NULL, false, '2026-09-28 21:15:53.111214+00', NULL);


--
-- Data for Name: one_time_prekeys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: reactions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: room_participants; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.room_participants (id, room_id, user_id, visible_from_id) VALUES (1, 934210995, 369265884, 0);
INSERT INTO public.room_participants (id, room_id, user_id, visible_from_id) VALUES (2, 934210995, 1955890954, 0);
INSERT INTO public.room_participants (id, room_id, user_id, visible_from_id) VALUES (3, 934210995, 1141387901, 0);
INSERT INTO public.room_participants (id, room_id, user_id, visible_from_id) VALUES (4, 2101399303, 1955890954, 0);


--
-- Data for Name: room_settings; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: rooms; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.rooms (id, name, code, created_at, code_expires_at, invite_max_members, invite_require_approval, invite_disabled) VALUES (934210995, 'Команда', '76X4CMW25RYCB9KQ8BGVCXUN5E', '2026-09-28 21:15:52.766977', '2026-10-05 21:15:52.766977+00', NULL, true, false);
INSERT INTO public.rooms (id, name, code, created_at, code_expires_at, invite_max_members, invite_require_approval, invite_disabled) VALUES (2101399303, 'Личное bob', 'DFM7VVMLFKZWSN4SV6QR33ZRTB', '2026-09-28 21:15:53.120842', '2026-10-05 21:15:53.120842+00', NULL, true, false);


--
-- Data for Name: security_events; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.security_events (id, user_id, type, client, created_at) VALUES (1, 369265884, 'register', 'Неизвестный клиент', '2026-09-28 21:15:51.734848+00');
INSERT INTO public.security_events (id, user_id, type, client, created_at) VALUES (2, 1955890954, 'register', 'Неизвестный клиент', '2026-09-28 21:15:52.230002+00');
INSERT INTO public.security_events (id, user_id, type, client, created_at) VALUES (3, 369265884, 'login', 'Неизвестный клиент', '2026-09-28 21:15:52.758029+00');


--
-- Data for Name: session; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.session (sid, sess, expire) VALUES ('lsdTxc30KijLjws7sTlHIs1EZhwt9kLA', '{"cookie":{"originalMaxAge":86400000,"expires":"2026-09-29T21:15:52.228Z","secure":false,"httpOnly":true,"path":"/","sameSite":"lax"},"userId":1955890954,"username":"bob","uniqueCode":"4d1PiFiT","avatar":"#667EEA"}', '2026-09-29 21:15:53');
INSERT INTO public.session (sid, sess, expire) VALUES ('Z6DHJQ6mfjY9r76NGajJ0sYDixNQg9nJ', '{"cookie":{"originalMaxAge":604800000,"expires":"2026-10-05T21:15:52.262Z","secure":false,"httpOnly":true,"path":"/","sameSite":"lax"},"userId":1141387901,"username":"Гость-RRBS","uniqueCode":"sMlzcAYf","avatar":"#667EEA","isAnonymous":true,"createdAt":1790630152260,"anonLifetime":"day"}', '2026-10-05 21:15:53');
INSERT INTO public.session (sid, sess, expire) VALUES ('V9D5vcrb1SJCWgCm4hxfGhGx0NPUMkBs', '{"cookie":{"originalMaxAge":86400000,"expires":"2026-09-29T21:15:52.756Z","secure":false,"httpOnly":true,"path":"/","sameSite":"lax"},"userId":369265884,"username":"alice","uniqueCode":"JODDBv6d","avatar":"#667EEA"}', '2026-09-29 21:15:53');


--
-- Data for Name: signed_pq_prekeys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: signed_prekeys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: unread; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.users (id, unique_code, username, email, password, avatar, created_at, read_receipts, anon_lifetime, last_active_at) VALUES (369265884, 'JODDBv6d', 'alice', 'alice@example.test', '$nyxo1$$2a$12$hpYDPm7ml7lALbd2HFFEceLh5STP4iCdHrojXq6TDDoMQcsQMFZ1C', '#667EEA', '2026-09-28 21:15:51.651851', true, NULL, NULL);
INSERT INTO public.users (id, unique_code, username, email, password, avatar, created_at, read_receipts, anon_lifetime, last_active_at) VALUES (1955890954, '4d1PiFiT', 'bob', 'bob@example.test', '$nyxo1$$2a$12$BvEw0YlPiAyyOeV5Caa1YOB8DwunhAVP1B82.10TGIJh3LnCJWVh2', '#667EEA', '2026-09-28 21:15:52.152141', true, NULL, NULL);
INSERT INTO public.users (id, unique_code, username, email, password, avatar, created_at, read_receipts, anon_lifetime, last_active_at) VALUES (1141387901, 'sMlzcAYf', 'Гость-RRBS', NULL, NULL, '#667EEA', '2026-09-28 21:15:52.252407', true, 'day', '2026-09-28 21:15:52.252407+00');


--
-- Name: chats_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.chats_id_seq', 1, false);


--
-- Name: e2ee_key_shares_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.e2ee_key_shares_id_seq', 1, false);


--
-- Name: messages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.messages_id_seq', 7, true);


--
-- Name: one_time_prekeys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.one_time_prekeys_id_seq', 1, false);


--
-- Name: reactions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.reactions_id_seq', 1, false);


--
-- Name: room_participants_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.room_participants_id_seq', 4, true);


--
-- Name: rooms_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.rooms_id_seq', 1, false);


--
-- Name: security_events_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.security_events_id_seq', 3, true);


--
-- Name: unread_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.unread_id_seq', 1, false);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.users_id_seq', 1, false);


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
-- Name: message_expiry message_expiry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_expiry
    ADD CONSTRAINT message_expiry_pkey PRIMARY KEY (message_id);


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
-- Name: room_participants room_participants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_participants
    ADD CONSTRAINT room_participants_pkey PRIMARY KEY (id);


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
-- Name: security_events security_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_pkey PRIMARY KEY (id);


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
-- Name: unread unread_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unread
    ADD CONSTRAINT unread_pkey PRIMARY KEY (id);


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
-- Name: idx_message_expiry_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_message_expiry_expires_at ON public.message_expiry USING btree (expires_at);


--
-- Name: idx_messages_chat_live; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_chat_live ON public.messages USING btree (chat_id, deleted, id) INCLUDE (user_id, sent, encrypted);


--
-- Name: idx_messages_file_url; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_file_url ON public.messages USING btree (file_url) WHERE (file_url IS NOT NULL);


--
-- Name: idx_messages_reply_to_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_reply_to_id ON public.messages USING btree (reply_to_id) WHERE (reply_to_id IS NOT NULL);


--
-- Name: idx_messages_room_live; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_room_live ON public.messages USING btree (room_id, deleted, id) INCLUDE (user_id, sent, encrypted);


--
-- Name: idx_messages_user_files; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_user_files ON public.messages USING btree (user_id) INCLUDE (file_size) WHERE (file_size IS NOT NULL);


--
-- Name: idx_messages_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_user_id ON public.messages USING btree (user_id);


--
-- Name: idx_otpk_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_otpk_user ON public.one_time_prekeys USING btree (user_id);


--
-- Name: idx_reactions_msg_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reactions_msg_user ON public.reactions USING btree (message_id, user_id);


--
-- Name: idx_room_participants_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_room_participants_unique ON public.room_participants USING btree (room_id, user_id);


--
-- Name: idx_room_participants_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_room_participants_user ON public.room_participants USING btree (user_id);


--
-- Name: idx_security_events_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_user ON public.security_events USING btree (user_id, id);


--
-- Name: idx_users_anon; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_anon ON public.users USING btree (created_at) WHERE ((email IS NULL) AND (password IS NULL));


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
    ADD CONSTRAINT messages_chat_id_fkey FOREIGN KEY (chat_id) REFERENCES public.chats(id) ON DELETE SET NULL;


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
-- Name: security_events security_events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: unread unread_chat_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unread
    ADD CONSTRAINT unread_chat_id_fkey FOREIGN KEY (chat_id) REFERENCES public.chats(id) ON DELETE CASCADE;


--
-- Name: unread unread_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unread
    ADD CONSTRAINT unread_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- PostgreSQL database dump complete
--


