import React, { useState, useMemo } from "react";
import { Finding, Severity } from "../types";
import { 
  ShieldCheck, 
  ShieldAlert, 
  Search, 
  Filter, 
  Terminal, 
  Activity, 
  FolderLock, 
  Key, 
  Braces, 
  HelpCircle, 
  Code,
  ArrowRight,
  Sparkles,
  RefreshCw,
  SlidersHorizontal,
  FileCheck,
  Building,
  ChevronDown,
  ChevronUp,
  Zap,
  Download
} from "lucide-react";

interface ResourceItem {
  id: string; // e.g. "aws_s3_bucket.prod_logs"
  type: string; // e.g. "aws_s3_bucket"
  name: string; // e.g. "prod_logs"
  status: "PASS" | "FAIL";
  findings: Finding[];
  attributes: Record<string, string>;
  rawCodeBlock: string;
}

interface InfrastructureInventoryProps {
  rawCode: string;
  findings: Finding[];
  setActiveTab: (tab: "dashboard" | "scan" | "chat" | "rego" | "logs" | "repository" | "inventory") => void;
  setExpandedFinding: (id: string | null) => void;
  onRemediateFinding?: (correctedBlock: string, findingId: string) => void;
}

export default function InfrastructureInventory({ 
  rawCode, 
  findings, 
  setActiveTab, 
  setExpandedFinding,
  onRemediateFinding 
}: InfrastructureInventoryProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<"ALL" | "PASS" | "FAIL">("ALL");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState<"ID_ASC" | "ID_DESC" | "FINDINGS_DESC" | "RISK_DESC">("ID_ASC");
  const [expandedResourceId, setExpandedResourceId] = useState<string | null>(null);

  // Parse resources from raw configuration code
  const resources = useMemo(() => {
    const list: ResourceItem[] = [];
    if (!rawCode) return list;

    // Clean comments first for scanner parity
    const cleanCode = rawCode.replace(/\s*#.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
    
    // Parse using exact resource block regex
    const resourceRegex = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)\}/g;
    let match;

    // Keep track of characters to grab the original code block with comments from the original rawCode
    while ((match = resourceRegex.exec(cleanCode)) !== null) {
      const type = match[1];
      const name = match[2];
      const body = match[3];
      const id = `${type}.${name}`;

      // Extract raw code block from original code if possible, or build fallback
      // Since cleanCode has matched start/end indices, let's look for resource "type" "name" in rawCode
      const rawBlockRegex = new RegExp(`resource\\s+"${type}"\\s+"${name}"\\s*\\{[\\s\\S]*?\\}`, "g");
      const blockMatch = rawBlockRegex.exec(rawCode);
      const rawCodeBlock = blockMatch ? blockMatch[0] : `resource "${type}" "${name}" {${body}}`;

      // Parse inner attributes lines
      const attributes: Record<string, string> = {};
      const lines = body.split("\n");
      lines.forEach(line => {
        const trimmed = line.trim();
        if (trimAndValidateAttribute(trimmed)) {
          const parts = trimmed.split("=");
          const k = parts[0].trim();
          let v = parts.slice(1).join("=").trim();
          // Remove wrapping quotes and commas
          v = v.replace(/^"|"$/g, "").replace(/^'|'$/g, "").replace(/,$/, "").trim();
          if (!k.includes("{") && !v.includes("{")) {
            attributes[k] = v;
          }
        }
      });

      // Filter findings mapped along this resource
      const resourceFindings = findings.filter(f => f.resource === id);
      const status = resourceFindings.length > 0 ? "FAIL" : "PASS";

      list.push({
        id,
        type,
        name,
        status,
        findings: resourceFindings,
        attributes,
        rawCodeBlock
      });
    }

    return list;
  }, [rawCode, findings]);

  // Check if standard text attribute line contains primitive assignment
  function trimAndValidateAttribute(line: string): boolean {
    if (!line || line.startsWith("#") || line.startsWith("//") || !line.includes("=")) {
      return false;
    }
    return true;
  }

  // Auto-calculated types list
  const availableTypes = useMemo(() => {
    const typesSet = new Set<string>();
    resources.forEach(r => typesSet.add(r.type));
    return Array.from(typesSet).sort();
  }, [resources]);

  // Filtered and sorted resources
  const filteredResources = useMemo(() => {
    let result = [...resources];

    // Search term match over ID, Type, attributes
    if (searchTerm) {
      const query = searchTerm.toLowerCase();
      result = result.filter(r => {
        const matchesId = r.id.toLowerCase().includes(query);
        const matchesType = r.type.toLowerCase().includes(query);
        const matchesAttr = Object.entries(r.attributes).some(
          ([k, v]) => k.toLowerCase().includes(query) || String(v).toLowerCase().includes(query)
        );
        return matchesId || matchesType || matchesAttr;
      });
    }

    // Status Filter
    if (statusFilter !== "ALL") {
      result = result.filter(r => r.status === statusFilter);
    }

    // Type Filter
    if (typeFilter !== "ALL") {
      result = result.filter(r => r.type === typeFilter);
    }

    // Sort evaluation
    result.sort((a, b) => {
      if (sortBy === "ID_ASC") {
        return a.id.localeCompare(b.id);
      }
      if (sortBy === "ID_DESC") {
        return b.id.localeCompare(a.id);
      }
      if (sortBy === "FINDINGS_DESC") {
        return b.findings.length - a.findings.length;
      }
      if (sortBy === "RISK_DESC") {
        const riskA = a.findings.reduce((sum, f) => sum + f.riskScore, 0);
        const riskB = b.findings.reduce((sum, f) => sum + f.riskScore, 0);
        return riskB - riskA;
      }
      return 0;
    });

    return result;
  }, [resources, searchTerm, statusFilter, typeFilter, sortBy]);

  // Aggregate Metrics block definitions
  const metrics = useMemo(() => {
    const totalCount = resources.length;
    const compliantCount = resources.filter(r => r.status === "PASS").length;
    const nonCompliantCount = totalCount - compliantCount;
    const complianceRate = totalCount > 0 ? Math.round((compliantCount / totalCount) * 100) : 100;

    let criticalCount = 0;
    let highCount = 0;
    let mediumOrLowCount = 0;

    findings.forEach(f => {
      if (f.severity === "critical") criticalCount++;
      else if (f.severity === "high") highCount++;
      else mediumOrLowCount++;
    });

    return {
      totalCount,
      compliantCount,
      nonCompliantCount,
      complianceRate,
      criticalCount,
      highCount,
      mediumOrLowCount
    };
  }, [resources, findings]);

  // Simple icon selector based on AWS resource types
  const getResourceIcon = (type: string) => {
    const t = type.toLowerCase();
    if (t.includes("s3") || t.includes("bucket")) return <FolderLock className="w-4 h-4 text-[#F27D26]" />;
    if (t.includes("security_group") || t.includes("network")) return <ShieldCheck className="w-4 h-4 text-[#00FF00]" />;
    if (t.includes("kms") || t.includes("key") || t.includes("encryption")) return <Key className="w-4 h-4 text-[#FFB300]" />;
    if (t.includes("iam") || t.includes("role") || t.includes("policy")) return <Braces className="w-4 h-4 text-[#A855F7]" />;
    if (t.includes("cloudtrail") || t.includes("audit") || t.includes("monitor")) return <Terminal className="w-4 h-4 text-[#06B6D4]" />;
    return <Building className="w-4 h-4 text-[#888]" />;
  };

  // Human-friendly resource type labels helper
  const friendlyTypeName = (type: string) => {
    const parts = type.split("_");
    return parts.map(p => p.charAt(0).toUpperCase() + p.slice(1)).join(" ");
  };

  return (
    <div className="space-y-8 animate-fade-in" id="inventory-module-root">
      
      {/* Metrics Row - Bento Grid Header */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        
        {/* Compliance Rating Widget */}
        <div className="bg-[#111] border border-[#222] p-6 flex flex-col justify-between">
          <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] block mb-2">Resource Coverage Ratio</span>
          <div className="flex items-baseline space-x-1.5 mt-2">
            <span className="text-5xl font-black font-mono text-white leading-none">{metrics.complianceRate}%</span>
            <span className="text-xs text-[#00FF00] font-mono uppercase font-bold">Compliant</span>
          </div>
          <div className="w-full bg-[#1A1A1A] h-1.5 rounded-none mt-4 overflow-hidden border border-[#222]">
            <div 
              className="bg-[#00FF00] h-full transition-all duration-500" 
              style={{ width: `${metrics.complianceRate}%` }}
            ></div>
          </div>
          <span className="text-[10px] text-[#555] font-mono mt-3 uppercase tracking-wider font-bold">
            {metrics.compliantCount} / {metrics.totalCount} Resources Sealed Secure
          </span>
        </div>

        {/* Total Tracked Resources */}
        <div className="bg-[#111] border border-[#222] p-6 flex flex-col justify-between">
          <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] block mb-2">Inventory Footprint</span>
          <div className="flex items-baseline space-x-1.5 mt-2">
            <span className="text-5xl font-black font-mono text-white leading-none">{metrics.totalCount}</span>
            <span className="text-xs text-[#888] font-mono uppercase font-bold">Tracked Node{metrics.totalCount !== 1 ? "s" : ""}</span>
          </div>
          <p className="text-[11px] text-[#555] font-sans mt-4 leading-relaxed">
            Resources dynamically discovered from active Terraform blueprint manifests.
          </p>
        </div>

        {/* Action Triage Count */}
        <div className="bg-[#111] border border-[#222] p-6 flex flex-col justify-between">
          <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] block mb-2">Active Violating States</span>
          <div className="flex items-baseline space-x-1.5 mt-2">
            <span className={`text-5xl font-black font-mono leading-none ${metrics.nonCompliantCount > 0 ? "text-[#FF3E3E]" : "text-white/40"}`}>{metrics.nonCompliantCount}</span>
            <span className="text-xs text-[#FF3E3E] font-mono uppercase font-bold">Critical Drift</span>
          </div>
          <p className="text-[11px] text-[#555] font-sans mt-4 leading-relaxed">
            Requires engineering compliance authorization and patch execution.
          </p>
        </div>

        {/* Hazard Summary Breakdown */}
        <div className="bg-[#111] border border-[#222] p-6 flex flex-col justify-between font-mono">
          <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] block mb-2">Threat Vector Grid</span>
          
          <div className="space-y-1.5 mt-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#FF0055] font-bold uppercase">Critical Hazards:</span>
              <span className="text-white font-black">{metrics.criticalCount}</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#FF3E3E] font-bold uppercase">High Risks:</span>
              <span className="text-white font-black">{metrics.highCount}</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#F27D26] font-bold uppercase">Medium/Low:</span>
              <span className="text-white font-black">{metrics.mediumOrLowCount}</span>
            </div>
          </div>
        </div>

      </div>

      {/* Control Filters Terminal Box */}
      <div className="bg-[#0A0A0A] border border-[#222] p-6">
        
        {/* Label block */}
        <div className="flex items-center space-x-2 text-[10px] text-[#555] uppercase tracking-[0.2em] font-bold mb-4">
          <SlidersHorizontal className="w-3.5 h-3.5 text-[#00FF00]" />
          <span>Inventory Telemetry Controls</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
          
          {/* Text Search Bar */}
          <div className="md:col-span-4 relative">
            <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#444]">
              <Search className="w-4 h-4" />
            </span>
            <input 
              type="text"
              placeholder="Filter by ID, parameter value, or class name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-[#111] border border-[#222] pl-10 pr-4 py-2 text-xs font-mono text-white placeholder-[#444] rounded-none focus:outline-none focus:border-[#00FF00] hover:border-[#333] transition-colors"
            />
          </div>

          {/* Compliance Status Selector */}
          <div className="md:col-span-2.5">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as "ALL" | "PASS" | "FAIL")}
              className="w-full bg-[#111] border border-[#222] px-3 py-2 text-xs font-mono text-white rounded-none focus:outline-none focus:border-[#00FF00] hover:border-[#333] transition-colors cursor-pointer"
            >
              <option value="ALL">Status: All Nodes</option>
              <option value="PASS">Secure Status (PASS)</option>
              <option value="FAIL">Critical State (FAIL)</option>
            </select>
          </div>

          {/* Resource Type Selector */}
          <div className="md:col-span-3">
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full bg-[#111] border border-[#222] px-3 py-2 text-xs font-mono text-white rounded-none focus:outline-none focus:border-[#00FF00] hover:border-[#333] transition-colors cursor-pointer"
            >
              <option value="ALL">Resource Class: All Classes</option>
              {availableTypes.map(t => (
                <option key={t} value={t}>{friendlyTypeName(t)} ({t})</option>
              ))}
            </select>
          </div>

          {/* Sort Selector */}
          <div className="md:col-span-2.5">
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="w-full bg-[#111] border border-[#222] px-3 py-2 text-xs font-mono text-white rounded-none focus:outline-none focus:border-[#00FF00] hover:border-[#333] transition-colors cursor-pointer"
            >
              <option value="ID_ASC">Sort: Alphabetical (A-Z)</option>
              <option value="ID_DESC">Sort: Alphabetical (Z-A)</option>
              <option value="FINDINGS_DESC">Sort: Most Violations</option>
              <option value="RISK_DESC">Sort: Overall Severity Scale</option>
            </select>
          </div>

        </div>

        {/* Counter feedback */}
        <div className="mt-4 pt-3.5 border-t border-[#1a1a1a] flex items-center justify-between text-[10px] font-mono text-[#555]">
          <span>Isolating {filteredResources.length} mapped database records</span>
          {searchTerm && (
            <button 
              onClick={() => setSearchTerm("")}
              className="text-[#888] hover:text-[#00FF00] uppercase font-bold tracking-wider"
            >
              Reset Terminal Query
            </button>
          )}
        </div>

      </div>

      {/* Main Grid/Inventory Database Table Panel */}
      <div className="bg-[#111] border border-[#222] overflow-hidden">
        
        {filteredResources.length === 0 ? (
          <div className="p-16 text-center select-none">
            <ShieldCheck className="w-12 h-12 text-[#555] mx-auto mb-4 opacity-40 animate-pulse" />
            <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] block">Zero Mapped Cloud Nodes Found</span>
            <p className="text-xs text-[#777] max-w-md mx-auto mt-2 leading-relaxed">
              No deployed resources match the selected filters or search parameters. Clear filters to restore tracking list.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-[#222]">
            {filteredResources.map((item) => {
              const totalRiskScore = item.findings.reduce((sum, f) => sum + f.riskScore, 0);
              const isExpanded = expandedResourceId === item.id;

              return (
                <div key={item.id} className={`transition-all ${item.status === "FAIL" ? "bg-[#160d0f]/15" : "bg-transparent"}`}>
                  
                  {/* Row Header Segment */}
                  <div 
                    onClick={() => setExpandedResourceId(isExpanded ? null : item.id)}
                    className="flex flex-col md:flex-row md:items-center justify-between p-5 md:p-6 gap-4 cursor-pointer hover:bg-[#1a1a1a] transition-all"
                  >
                    
                    {/* Left: Resource Identifiers and Icon */}
                    <div className="flex items-start space-x-3.5 min-w-0">
                      <div className="p-2 border border-[#222] bg-[#0A0A0A] shrink-0">
                        {getResourceIcon(item.type)}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                          <span className="text-[10px] text-[#555] font-mono font-bold uppercase tracking-wider">{item.type}</span>
                          <span className="text-[#333] hidden md:inline">•</span>
                          <span className="text-[9px] bg-[#1a1c1a]/80 text-[#FFF] font-mono border border-[#333] px-2 py-0.5 uppercase tracking-tighter">
                            {friendlyTypeName(item.type)} class
                          </span>
                        </div>
                        <h4 className="text-sm font-bold font-mono text-white mt-1 select-all truncate block">
                          {item.id}
                        </h4>
                      </div>
                    </div>

                    {/* Right: Score/Fails/Metadata Badging */}
                    <div className="flex items-center space-x-5 self-end md:self-center shrink-0">
                      
                      {/* Findings count badge */}
                      {item.status === "FAIL" ? (
                        <div className="text-right">
                          <span className="text-[9px] text-[#FF3E3E] font-mono font-black border border-[#FF3E3E]/30 bg-[#2d1112]/50 px-2.5 py-1 uppercase tracking-wider inline-flex items-center space-x-1.5 animate-pulse">
                            <ShieldAlert className="w-3 h-3" />
                            <span>{item.findings.length} Threat{item.findings.length > 1 ? "s" : ""}</span>
                          </span>
                          <span className="text-[10px] text-[#555] font-mono block mt-1">Severity Score: {totalRiskScore}</span>
                        </div>
                      ) : (
                        <div className="text-right">
                          <span className="text-[9px] text-[#00FF00] font-mono font-bold border border-[#00FF00]/20 bg-[#0c1c11] px-2.5 py-1 uppercase tracking-wider inline-flex items-center space-x-1.5">
                            <ShieldCheck className="w-3 h-3" />
                            <span>Compliant</span>
                          </span>
                          <span className="text-[10px] text-[#555] font-mono block mt-1">Status: Stable</span>
                        </div>
                      )}

                      {/* Expand / Collapse Indicator */}
                      <div className="text-[#555] hover:text-white transition-colors">
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </div>

                    </div>

                  </div>

                  {/* Expanded Inspector Panel Segment */}
                  {isExpanded && (
                    <div className="border-t border-[#222] bg-[#070707] p-6 lg:p-8 animate-fade-in divide-y divide-[#222]/60 space-y-6">
                      
                      {/* Meta Parameters Block */}
                      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pb-6">
                        
                        {/* Attributes Dictionary list */}
                        <div className="lg:col-span-5 space-y-3 font-mono">
                          <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] border-b border-[#222] pb-1.5 select-none">
                            Discovered Static Attributes
                          </div>
                          {Object.keys(item.attributes).length === 0 ? (
                            <div className="text-xs text-[#555] py-2 italic font-serif">
                              No explicit static metadata parameters declared in baseline configuration file.
                            </div>
                          ) : (
                            <div className="space-y-2 bg-[#050505] border border-[#222] p-4 text-xs">
                              {Object.entries(item.attributes).map(([k, v]) => (
                                <div key={k} className="flex justify-between items-start gap-4">
                                  <span className="text-[#888] font-bold mr-2 shrink-0">{k}</span>
                                  <span className="text-white text-right select-all font-mono tracking-tighter max-w-[200px] truncate" title={v}>
                                    {v}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>

                        {/* Resource configuration block */}
                        <div className="lg:col-span-7 space-y-3 font-mono">
                          <div className="flex items-center justify-between text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] border-b border-[#222] pb-1.5 select-none">
                            <span>Manifest Sub-Tree Structure</span>
                            <span className="text-[8px] bg-[#111] px-2 py-0.5 border border-[#222] rounded-none">HCL-v12.0</span>
                          </div>
                          <div className="bg-[#030303] border border-[#222] p-4 text-xs text-[#CCC] font-mono overflow-x-auto select-text relative leading-relaxed max-h-[220px]">
                            {item.rawCodeBlock}
                          </div>
                        </div>

                      </div>

                      {/* Active Compliance Warnings Sublist */}
                      {item.status === "FAIL" && (
                        <div className="pt-6">
                          <div className="text-[10px] font-bold font-mono uppercase tracking-[0.2em] text-[#FF3E3E] mb-4 select-none">
                            Active Hard-Stop Compliance Warnings ({item.findings.length})
                          </div>
                          <div className="space-y-4">
                            {item.findings.map(finding => (
                              <div key={finding.id} className="bg-[#1C1111] border border-[#FF3E3E]/25 p-5">
                                <div className="flex items-start justify-between flex-wrap gap-2">
                                  <div>
                                    <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                                      <span className="text-[9px] bg-[#330c14] text-[#FF0055] border border-[#FF0055]/30 px-2 py-0.5 uppercase tracking-wider font-extrabold font-mono">
                                        {finding.severity}
                                      </span>
                                      <span className="text-[9px] bg-[#1a1111] text-[#FF3E3E] border border-[#FF3E3E]/30 px-2 py-0.5 uppercase tracking-wider font-bold font-mono">
                                        {finding.framework} — CC Code: {finding.controlId}
                                      </span>
                                      <span className="text-[10px] text-[#A855F7] font-mono leading-none font-bold">OPA Rule: {finding.ruleName}</span>
                                    </div>
                                    <h5 className="text-white font-mono text-sm mt-3 font-bold">{finding.finding}</h5>
                                    <p className="text-xs text-[#AAA] font-sans mt-2 leading-relaxed max-w-4xl">{finding.whyItHappened}</p>
                                  </div>

                                  {/* Right side quick stats */}
                                  <div className="text-right font-mono self-start">
                                    <span className="text-[10px] text-[#555] uppercase block font-bold">Threat Matrix Coords</span>
                                    <span className="text-xs text-[#FF3E3E] font-black">
                                      L:{finding.likelihood} x I:{finding.impact} x E:{finding.exposure}
                                    </span>
                                    <span className="text-[10px] text-[#FF3E3E]/80 block font-black mt-1">Score: {finding.riskScore}</span>
                                  </div>
                                </div>

                                {/* Suggested Remediation Code snippet */}
                                {finding.remediation && (
                                  <div className="mt-5 space-y-2.5">
                                    <span className="text-[10px] text-[#555] font-mono block uppercase font-bold select-none">GRC Suggested Remediation Code Block</span>
                                    <div className="bg-[#050505] border border-[#222] p-4 text-xs text-[#00FF00] font-mono overflow-x-auto relative leading-relaxed max-h-[160px]">
                                      {finding.remediation}
                                    </div>
                                    <div className="flex items-center justify-end space-x-3 pt-2">
                                      {onRemediateFinding && (
                                        <button
                                          onClick={() => onRemediateFinding(finding.remediation, finding.id)}
                                          className="text-[10px] bg-[#00FF00]/10 hover:bg-[#00FF00] text-[#00FF00] hover:text-black border border-[#00FF00]/25 px-4.5 py-2 font-mono font-black uppercase tracking-widest transition-all inline-flex items-center space-x-1.5 cursor-pointer"
                                        >
                                          <Zap className="w-3.5 h-3.5" />
                                          <span>Run Self-Healing Remediation Loop</span>
                                        </button>
                                      )}
                                      <button
                                        onClick={() => {
                                          setActiveTab("scan");
                                          setExpandedFinding(finding.id);
                                        }}
                                        className="text-[10px] bg-white hover:bg-[#00FF00] text-black font-mono font-black uppercase tracking-widest px-4.5 py-2 transition-all inline-flex items-center space-x-1 cursor-pointer"
                                      >
                                        <span>Full Analysis Workspace</span>
                                        <ArrowRight className="w-3.5 h-3.5" />
                                      </button>
                                    </div>
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Compliant resource message */}
                      {item.status === "PASS" && (
                        <div className="bg-[#0c1c11]/25 border border-[#00FF00]/15 p-5 pt-6 text-sm text-[#00FF00]/80">
                          <div className="flex items-center space-x-2">
                            <ShieldCheck className="w-4 h-4 shrink-0" />
                            <span className="font-mono font-black uppercase text-[10px] tracking-widest">Cryptographic Compliance Attestation Granted</span>
                          </div>
                          <p className="text-xs text-[#777] font-sans mt-2.5 leading-relaxed max-w-4xl">
                            This resource exhibits perfect parameters corresponding to pre-mapped controls defined in socio-technical governance protocols. Dynamic configuration auditing registers a stable compliant operational lifecycle state.
                          </p>
                        </div>
                      )}

                    </div>
                  )}

                </div>
              );
            })}
          </div>
        )}

      </div>
    </div>
  );
}
