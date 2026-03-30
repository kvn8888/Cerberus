// Run this first — before any data import.
// Uniqueness constraints enable MERGE dedup and prevent duplicate nodes.

CREATE CONSTRAINT pkg_name IF NOT EXISTS
  FOR (p:Package) REQUIRE p.name IS UNIQUE;

CREATE CONSTRAINT cve_id IF NOT EXISTS
  FOR (c:CVE) REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT ip_addr IF NOT EXISTS
  FOR (i:IP) REQUIRE i.address IS UNIQUE;

CREATE CONSTRAINT domain_name IF NOT EXISTS
  FOR (d:Domain) REQUIRE d.name IS UNIQUE;

CREATE CONSTRAINT actor_name IF NOT EXISTS
  FOR (ta:ThreatActor) REQUIRE ta.name IS UNIQUE;

CREATE CONSTRAINT technique_id IF NOT EXISTS
  FOR (t:Technique) REQUIRE t.mitre_id IS UNIQUE;

CREATE CONSTRAINT account_key IF NOT EXISTS
  FOR (a:Account) REQUIRE (a.username, a.registry) IS UNIQUE;

CREATE CONSTRAINT fraud_id IF NOT EXISTS
  FOR (fs:FraudSignal) REQUIRE fs.juspay_id IS UNIQUE;
