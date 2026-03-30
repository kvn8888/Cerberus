// ============================================================
// Cerberus — Neo4j Uniqueness Constraints
// ============================================================
// Run ALL of these BEFORE any data imports.
// These constraints serve two purposes:
//   1. MERGE operations use them for dedup (fast index lookup
//      instead of full label scan)
//   2. Prevent duplicate nodes during rapid concurrent import
//
// Run against Neo4j Aura via browser console, neo4j-mcp, or
// the Python driver. Order doesn't matter — they're independent.
// ============================================================

// Package nodes are unique by name (e.g., "ua-parser-js")
CREATE CONSTRAINT pkg_name IF NOT EXISTS FOR (p:Package) REQUIRE p.name IS UNIQUE;

// CVE nodes are unique by their standard ID (e.g., "CVE-2021-27292")
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE;

// IP nodes are unique by address (e.g., "203.0.113.42")
CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE;

// Domain nodes are unique by fully-qualified domain name
CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;

// ThreatActor nodes are unique by name/alias
CREATE CONSTRAINT actor_name IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.name IS UNIQUE;

// MITRE ATT&CK Technique nodes are unique by their MITRE ID (e.g., "T1195.002")
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.mitre_id IS UNIQUE;

// Account nodes are unique by the combination of username + registry
// (same username on npm vs pypi are different accounts)
CREATE CONSTRAINT account_key IF NOT EXISTS FOR (a:Account) REQUIRE (a.username, a.registry) IS UNIQUE;

// FraudSignal nodes are unique by their Juspay transaction ID
CREATE CONSTRAINT fraud_id IF NOT EXISTS FOR (fs:FraudSignal) REQUIRE fs.juspay_id IS UNIQUE;
