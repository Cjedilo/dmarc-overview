-- Run once as the 'postgres' superuser on 192.168.93.11.
-- Creates the role + schema the cron script uses.
-- The script itself creates the tables (CREATE TABLE IF NOT EXISTS) on every run.

CREATE ROLE dmarc WITH LOGIN PASSWORD 'dmarc';

CREATE DATABASE dmarc OWNER dmarc;

\connect dmarc

CREATE SCHEMA dmarc AUTHORIZATION dmarc;
