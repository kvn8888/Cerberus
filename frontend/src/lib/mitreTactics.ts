/**
 * MITRE ATT&CK Enterprise tactics + technique ID to primary tactic (heatmap).
 */
export const MITRE_TACTICS_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

const T_TO_TACTIC: Record<string, string> = {
  T1595: "Reconnaissance",
  T1592: "Reconnaissance",
  T1583: "Resource Development",
  T1584: "Resource Development",
  T1587: "Resource Development",
  T1588: "Resource Development",
  T1195: "Initial Access",
  T1190: "Initial Access",
  T1133: "Initial Access",
  T1566: "Initial Access",
  T1078: "Initial Access",
  T1200: "Initial Access",
  T1059: "Execution",
  T1204: "Execution",
  T1053: "Persistence",
  T1547: "Persistence",
  T1136: "Persistence",
  T1543: "Persistence",
  T1037: "Persistence",
  T1546: "Persistence",
  T1134: "Privilege Escalation",
  T1548: "Privilege Escalation",
  T1055: "Defense Evasion",
  T1070: "Defense Evasion",
  T1027: "Defense Evasion",
  T1553: "Defense Evasion",
  T1562: "Defense Evasion",
  T1110: "Credential Access",
  T1555: "Credential Access",
  T1556: "Credential Access",
  T1040: "Discovery",
  T1018: "Discovery",
  T1082: "Discovery",
  T1016: "Discovery",
  T1049: "Discovery",
  T1091: "Lateral Movement",
  T1021: "Lateral Movement",
  T1020: "Collection",
  T1005: "Collection",
  T1114: "Collection",
  T1071: "Command and Control",
  T1105: "Command and Control",
  T1573: "Command and Control",
  T1048: "Exfiltration",
  T1486: "Impact",
  T1498: "Impact",
  T1485: "Impact",
  T1561: "Impact",
  T1499: "Impact",
  T1489: "Impact",
  T1496: "Impact",
};

export function extractTechniqueId(text: string): string | null {
  const m = text.match(/\b(T\d{4}(?:\.\d{3})?)\b/i);
  return m ? m[1].toUpperCase().split(".")[0]! : null;
}

export function tacticForTechniqueId(techniqueId: string): string {
  const base = techniqueId.toUpperCase().split(".")[0]!;
  return T_TO_TACTIC[base] ?? "Discovery";
}
