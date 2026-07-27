-- Eenmalig uit te voeren als 'postgres' superuser op 192.168.93.11.
-- Maakt de rol + schema aan die het cronscript gebruikt.
-- Tabellen maakt het script zelf aan (CREATE TABLE IF NOT EXISTS) bij elke run.

CREATE ROLE dmarc WITH LOGIN PASSWORD 'dmarc';

CREATE DATABASE dmarc OWNER dmarc;

\connect dmarc

CREATE SCHEMA dmarc AUTHORIZATION dmarc;
