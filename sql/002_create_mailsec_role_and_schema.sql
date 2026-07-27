-- Run once as the 'postgres' superuser on 192.168.93.11.
-- Creates the role + schema the mail-security log ingestion script (running
-- on the mail server, 192.168.93.10) uses. Separate role/schema from the
-- dmarc one, on purpose: least privilege, this script has nothing to do with
-- DMARC report data and shouldn't be able to touch it.
--
-- Unlike the dmarc role, this one needs to log in *remotely* (from .10), so
-- pick a real password, not a placeholder. See app.py deployment notes for
-- the matching pg_hba.conf / postgresql.conf / ufw changes.

CREATE ROLE mailsec WITH LOGIN PASSWORD 'mailsec';

\connect dmarc

CREATE SCHEMA mailsec AUTHORIZATION mailsec;
