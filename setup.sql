-- Run this in MySQL Workbench before starting either app for the first time

-- secure version database
CREATE DATABASE IF NOT EXISTS payroll_db;

-- insecure version database (separate so they don't share data)
CREATE DATABASE IF NOT EXISTS payroll_insecure_db;
