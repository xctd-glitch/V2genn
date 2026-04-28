-- ============================================================
-- notrackng.comv2 — Full Database Schema
-- MySQL 5.7+ / MariaDB 10.3+
-- Updated: 2026-04-17
-- ============================================================
-- Run once during the initial installation.
-- All DDL uses IF NOT EXISTS, so it is safe to re-run
-- on an existing database (idempotent).
-- ============================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;

-- ============================================================
-- Table: app_users
-- Application user accounts (sl.php & index.php dashboards).
-- cf_* : per-user Cloudflare credentials (global override).
-- ============================================================
CREATE TABLE IF NOT EXISTS `app_users` (
    `id`            INT              NOT NULL AUTO_INCREMENT,
    `username`      VARCHAR(50)      NOT NULL,
    `password_hash` VARCHAR(255)     NOT NULL,
    `domain`        VARCHAR(255)     NOT NULL DEFAULT '',
    `cf_token`      VARCHAR(255)     NOT NULL DEFAULT '',
    `cf_account_id` VARCHAR(100)     NOT NULL DEFAULT '',
    `cf_zone_id`    VARCHAR(100)     NOT NULL DEFAULT '',
    `cf_proxied`    VARCHAR(10)      NOT NULL DEFAULT 'true',
    `created_at`    TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: short_links
-- Shortlink data with smart routing support.
-- user_id          : link owner (ref app_users.id, 0 = admin)
-- rand_sub         : random subdomain generated on create
-- owner            : owner username (denormalized for faster queries)
-- redirect_url     : URL redirect final (override default_url)
-- country_rules    : JSON {"PH":"url","MY":"url"}
-- smartlink_ids    : JSON array of smartlinks.id
-- shimlink         : 'wl' | 'fb' | '' — wrapper shimlink
-- short_service    : 'own' | 'isgd' | 'vgd' | 'tinyurl'
-- external_url     : result from an external shortening service
-- ============================================================
CREATE TABLE IF NOT EXISTS `short_links` (
    `id`                INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `slug`              VARCHAR(30)      NOT NULL,
    `title`             VARCHAR(255)     NOT NULL DEFAULT '',
    `description`       TEXT,
    `image`             VARCHAR(500)     NOT NULL DEFAULT '',
    `default_url`       TEXT             NOT NULL,
    `redirect_url`      TEXT,
    `country_rules`     TEXT,
    `domain`            VARCHAR(255)     NOT NULL DEFAULT '',
    `smartlink_id`      INT UNSIGNED     NOT NULL DEFAULT 0,
    `smartlink_ids`     TEXT,
    `smartlink_network` VARCHAR(50)      NOT NULL DEFAULT '',
    `shimlink`          VARCHAR(10)      NOT NULL DEFAULT '',
    `link_type`         VARCHAR(10)      NOT NULL DEFAULT 'normal',
    `short_service`     VARCHAR(20)      NOT NULL DEFAULT 'own',
    `external_url`      TEXT,
    `hits`              INT UNSIGNED     NOT NULL DEFAULT 0,
    `active`            TINYINT(1)       NOT NULL DEFAULT 1,
    `user_id`           INT UNSIGNED     NOT NULL DEFAULT 0,
    `rand_sub`          VARCHAR(20)      NOT NULL DEFAULT '',
    `owner`             VARCHAR(50)      NOT NULL DEFAULT '',
    `created_by`        VARCHAR(50)      NOT NULL DEFAULT '',
    `created_at`        TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`        TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_slug`               (`slug`),
    KEY        `idx_active`            (`active`),
    KEY        `idx_user_id`           (`user_id`),
    KEY        `idx_user_active`       (`user_id`, `active`),
    KEY        `idx_smartlink_network` (`smartlink_network`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: smartlinks
-- Target URLs for smart traffic routing.
-- country : 'all' | ISO-3166-1 alpha-2 code, comma-separated (e.g. "PH,MY,SG")
-- device  : 'all' | 'mobile' | 'desktop'
-- network : 'direct' | 'fb' | 'google' | 'organic' | 'tiktok' | custom
-- ============================================================
CREATE TABLE IF NOT EXISTS `smartlinks` (
    `id`         INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `country`    TEXT             NOT NULL,
    `device`     VARCHAR(10)      NOT NULL DEFAULT 'all',
    `network`    VARCHAR(50)      NOT NULL DEFAULT 'direct',
    `url`        TEXT             NOT NULL,
    `created_at` TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_network` (`network`),
    KEY `idx_device`  (`device`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: addondomain
-- Addon domains managed through cPanel + Cloudflare.
-- sub_domain : '' = not synced yet | 'GLOBAL' = Cloudflare already active
-- domain_id  : owner identifier ('admin' | username)
-- ============================================================
CREATE TABLE IF NOT EXISTS `addondomain` (
    `id`         INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `sub_domain` VARCHAR(255)     NOT NULL DEFAULT '',
    `domain_id`  VARCHAR(100)     NOT NULL DEFAULT '',
    `domain`     VARCHAR(255)     NOT NULL,
    `created_at` TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_domain`     (`domain`),
    KEY        `idx_domain`    (`domain`),
    KEY        `idx_domain_id` (`domain_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: user_domains
-- User-owned custom domains (managed independently, not cPanel addon domains).
-- user_id = 0 : domain global / admin
-- ============================================================
CREATE TABLE IF NOT EXISTS `user_domains` (
    `id`         INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `user_id`    INT UNSIGNED     NOT NULL DEFAULT 0,
    `domain`     VARCHAR(255)     NOT NULL,
    `created_at` TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_user_domain` (`user_id`, `domain`),
    KEY        `idx_ud_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: link_hits
-- Daily click statistics per link (aggregated analytics).
-- UNIQUE KEY prevents duplicates - insert via:
--   INSERT ... ON DUPLICATE KEY UPDATE hits = hits + 1
-- ============================================================
CREATE TABLE IF NOT EXISTS `link_hits` (
    `id`       BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    `link_id`  INT UNSIGNED     NOT NULL DEFAULT 0,
    `slug`     VARCHAR(30)      CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    `hit_date` DATE             NOT NULL,
    `country`  VARCHAR(5)       NOT NULL DEFAULT '',
    `device`   VARCHAR(10)      NOT NULL DEFAULT '',
    `network`  VARCHAR(50)      NOT NULL DEFAULT '',
    `hits`     INT UNSIGNED     NOT NULL DEFAULT 1,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uniq_lh`       (`slug`, `hit_date`, `country`, `device`, `network`),
    KEY        `idx_lh_slug`   (`slug`),
    KEY        `idx_lh_date`   (`hit_date`),
    KEY        `idx_lh_linkid` (`link_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: postbacks
-- Postback URL configuration per user/slug for conversion notifications.
-- event : 'click' | 'conversion'
-- ============================================================
CREATE TABLE IF NOT EXISTS `postbacks` (
    `id`         INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `user_id`    INT UNSIGNED     NOT NULL DEFAULT 0,
    `name`       VARCHAR(100)     NOT NULL DEFAULT '',
    `slug`       VARCHAR(30)      NOT NULL DEFAULT '',
    `url`        TEXT             NOT NULL,
    `event`      VARCHAR(20)      NOT NULL DEFAULT 'click',
    `active`     TINYINT(1)       NOT NULL DEFAULT 1,
    `created_at` TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_pb_user`        (`user_id`),
    KEY `idx_pb_slug`        (`slug`),
    KEY `idx_pb_active_event`(`active`, `event`, `slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: clicks
-- Individual click events for conversion tracking.
-- clickid : base64url-encoded, format: subid,country,device,network,ip
--           (legacy pipe-separated: owner|country|device|ip|network)
-- subid   : sub ID from the affiliate network
-- payout  : accumulated payout from related conversions
-- ============================================================
CREATE TABLE IF NOT EXISTS `clicks` (
    `id`         BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    `user_id`    INT UNSIGNED     NOT NULL DEFAULT 0,
    `slug`       VARCHAR(30)      NOT NULL DEFAULT '',
    `clickid`    VARCHAR(255)     NOT NULL DEFAULT '',
    `subid`      VARCHAR(100)     NOT NULL DEFAULT '',
    `country`    VARCHAR(5)       NOT NULL DEFAULT '',
    `device`     VARCHAR(10)      NOT NULL DEFAULT '',
    `network`    VARCHAR(50)      NOT NULL DEFAULT '',
    `ip`         VARCHAR(45)      NOT NULL DEFAULT '',
    `payout`     DECIMAL(10,4)    NOT NULL DEFAULT 0.0000,
    `created_at` TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_cl_user`         (`user_id`),
    KEY `idx_cl_slug`         (`slug`),
    KEY `idx_cl_clickid`      (`clickid`(100)),
    KEY `idx_cl_created`      (`created_at`),
    KEY `idx_cl_clickid_slug` (`clickid`(100), `slug`),
    KEY `idx_cl_slug_created` (`slug`, `created_at`),
    KEY `idx_cl_user_created` (`user_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: conversions
-- Incoming conversion postbacks from the affiliate network.
-- Received via /postback endpoint (recv.php).
-- Accepts clickid parameter as: clickid, cid, click_id (all base64url-decoded).
-- status     : 'approved' | 'pending' | 'rejected' | 'declined'
-- raw_params : raw postback query string for debugging
-- source_ip  : sender IP of the postback request
-- ============================================================
CREATE TABLE IF NOT EXISTS `conversions` (
    `id`         BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    `user_id`    INT UNSIGNED     NOT NULL DEFAULT 0,
    `clickid`    VARCHAR(255)     NOT NULL DEFAULT '',
    `subid`      VARCHAR(100)     NOT NULL DEFAULT '',
    `slug`       VARCHAR(30)      NOT NULL DEFAULT '',
    `country`    VARCHAR(5)       NOT NULL DEFAULT '',
    `device`     VARCHAR(10)      NOT NULL DEFAULT '',
    `network`    VARCHAR(50)      NOT NULL DEFAULT '',
    `payout`     DECIMAL(10,4)    NOT NULL DEFAULT 0.0000,
    `status`     VARCHAR(20)      NOT NULL DEFAULT 'approved',
    `raw_params` TEXT,
    `source_ip`  VARCHAR(45)      NOT NULL DEFAULT '',
    `created_at` TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_cv_user`         (`user_id`),
    KEY `idx_cv_slug`         (`slug`),
    KEY `idx_cv_clickid`      (`clickid`(100)),
    KEY `idx_cv_status`       (`status`),
    KEY `idx_cv_created`      (`created_at`),
    KEY `idx_cv_slug_created` (`slug`, `created_at`),
    KEY `idx_cv_user_created` (`user_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: redirect_network_profile_cache
-- Cache of resolved network profiles per IP (go.php).
-- Managed by: PdoNetworkProfileCacheRepository
-- TTL is controlled by env REDIRECT_PROFILE_CACHE_TTL (seconds).
-- ============================================================
CREATE TABLE IF NOT EXISTS `redirect_network_profile_cache` (
    `ip`              VARCHAR(64)      NOT NULL,
    `country_code`    CHAR(2)          NOT NULL DEFAULT '',
    `asn`             BIGINT           NOT NULL DEFAULT 0,
    `organization`    VARCHAR(255)     NOT NULL DEFAULT '',
    `is_vpn`          TINYINT(1)       NOT NULL DEFAULT 0,
    `is_proxy`        TINYINT(1)       NOT NULL DEFAULT 0,
    `is_hosting`      TINYINT(1)       NOT NULL DEFAULT 0,
    `sources_json`    TEXT             NOT NULL,
    `checked_at_unix` BIGINT           NOT NULL,
    `expires_at_unix` BIGINT           NOT NULL,
    PRIMARY KEY (`ip`),
    KEY `idx_redirect_network_profile_cache_expires` (`expires_at_unix`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: redirect_decision_audit_log
-- Audit log of redirect decisions per request (sampled).
-- Sample rate is controlled by env REDIRECT_DECISION_AUDIT_SAMPLE_RATE.
-- Managed by: PdoDecisionAuditRepository
-- ============================================================
CREATE TABLE IF NOT EXISTS `redirect_decision_audit_log` (
    `id`                    BIGINT           NOT NULL AUTO_INCREMENT,
    `created_at_unix`       BIGINT           NOT NULL,
    `link_id`               BIGINT           NOT NULL DEFAULT 0,
    `slug`                  VARCHAR(191)     NOT NULL,
    `decision`              VARCHAR(32)      NOT NULL,
    `primary_reason`        VARCHAR(64)      NOT NULL,
    `window_mode`           VARCHAR(16)      NOT NULL,
    `delivery_outcome`      VARCHAR(24)      NOT NULL,
    `country_code`          CHAR(2)          NOT NULL DEFAULT '',
    `device`                VARCHAR(16)      NOT NULL DEFAULT '',
    `visitor_network`       VARCHAR(64)      NOT NULL DEFAULT '',
    `is_vpn_like`           TINYINT(1)       NOT NULL DEFAULT 0,
    `is_bot`                TINYINT(1)       NOT NULL DEFAULT 0,
    `profile_country_code`  CHAR(2)          NOT NULL DEFAULT '',
    `profile_asn`           BIGINT           NOT NULL DEFAULT 0,
    `profile_organization`  VARCHAR(255)     NOT NULL DEFAULT '',
    `provider_sources_json` JSON             NOT NULL,
    `reasons_json`          JSON             NOT NULL,
    `target_host`           VARCHAR(255)     NOT NULL DEFAULT '',
    `redirect_host`         VARCHAR(255)     NOT NULL DEFAULT '',
    PRIMARY KEY (`id`),
    KEY `idx_redirect_decision_audit_log_created`      (`created_at_unix`),
    KEY `idx_redirect_decision_audit_log_slug`         (`slug`),
    KEY `idx_redirect_decision_audit_log_decision`     (`decision`),
    KEY `idx_redirect_decision_audit_log_slug_created` (`slug`, `created_at_unix`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table: redirect_decision_metrics
-- Aggregated metrics per time bucket for health monitoring.
-- Composite PK prevents duplicates - insert via:
--   INSERT ... ON DUPLICATE KEY UPDATE total_count = total_count + 1
-- Managed by: PdoDecisionAuditRepository
-- ============================================================
CREATE TABLE IF NOT EXISTS `redirect_decision_metrics` (
    `bucket_unix`    BIGINT           NOT NULL,
    `slug`           VARCHAR(191)     NOT NULL,
    `decision`       VARCHAR(32)      NOT NULL,
    `primary_reason` VARCHAR(64)      NOT NULL,
    `window_mode`    VARCHAR(16)      NOT NULL,
    `country_code`   CHAR(2)          NOT NULL DEFAULT '',
    `device`         VARCHAR(16)      NOT NULL DEFAULT '',
    `total_count`    BIGINT           NOT NULL DEFAULT 0,
    PRIMARY KEY (`bucket_unix`, `slug`, `decision`, `primary_reason`, `window_mode`, `country_code`, `device`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET foreign_key_checks = 1;

-- ============================================================
-- EXISTING INSTALL NOTES
-- ============================================================
-- This file is intentionally rerunnable for fresh installs and schema replays.
-- Existing-install hot indexes are normalized by:
--   1. install.php -> installerApplyMysqlHotIndexes()
--   2. ops/ensure_mysql_hot_indexes.php
--
-- Routing notes:
--   /recv.php is also accessible via /postback (.htaccess)
--   recv.php accepts clickid aliases: clickid, cid, click_id

-- ============================================================
-- TABLE SUMMARY (12 tables)
-- ============================================================
-- Core:
--   app_users                      — user accounts & per-user Cloudflare credentials
--   short_links                    — shortlink + smart routing config
--   smartlinks                     — target URL routing rules
--   addondomain                    — domain addon cPanel + CF sync status
--   user_domains                   — domain custom per user
-- Analytics:
--   link_hits                      — aggregated daily clicks per link
--   postbacks                      — notification postback configuration
--   clicks                         — individual click events (conversion tracking)
--   conversions                    — conversion postbacks from the affiliate network
-- Redirect Decision Engine:
--   redirect_network_profile_cache — network profile cache per IP (TTL-based)
--   redirect_decision_audit_log    — redirect decision audit log (sampled)
--   redirect_decision_metrics      — aggregated metrics per time-bucket
-- ============================================================
