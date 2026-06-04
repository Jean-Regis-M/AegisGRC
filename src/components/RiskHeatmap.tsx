import React, { useState, useMemo } from "react";
import { Finding, Severity } from "../types";
import { 
  AlertTriangle, 
  CheckCircle, 
  Flame, 
  ShieldAlert, 
  X, 
  ChevronRight, 
  ArrowUpRight, 
  Layers, 
  Activity,
  HeartPulse,
  Sparkles,
  Zap
} from "lucide-react";

interface RiskHeatmapProps {
  findings: Finding[];
  setActiveTab: (tab: "dashboard" | "scan" | "chat" | "rego" | "logs" | "repository" | "inventory") => void;
  setExpandedFinding: (id: string | null) => void;
  onRemediateFinding?: (correctedBlock: string, findingId: string) => void;
}

export default function RiskHeatmap({ 
  findings, 
  setActiveTab, 
  setExpandedFinding,
  onRemediateFinding 
}: RiskHeatmapProps) {
  // Store selected coordinate state: [likelihood, impact] or null
  const [selectedCoord, setSelectedCoord] = useState<[number, number] | null>(null);

  // Group findings by likelihood and impact
  const gridData = useMemo(() => {
    const matrix: Record<string, Finding[]> = {};
    for (let l = 1; l <= 5; l++) {
      for (let i = 1; i <= 5; i++) {
        matrix[`${l}-${i}`] = [];
      }
    }
    findings.forEach(finding => {
      const key = `${finding.likelihood}-${finding.impact}`;
      if (matrix[key]) {
        matrix[key].push(finding);
      }
    });
    return matrix;
  }, [findings]);

  // Determine active filtered findings based on selected cell
  const filteredFindings = useMemo(() => {
    if (!selectedCoord) return [];
    const [l, i] = selectedCoord;
    return gridData[`${l}-${i}`] || [];
  }, [selectedCoord, gridData]);

  // Total findings across the entire active spectrum
  const activeViolationCount = findings.length;

  // Render color based on standard Risk Matrix Level (Likelihood * Impact)
  const getCellStyles = (l: number, i: number, isSelected: boolean, count: number) => {
    const riskVal = l * i;
    
    // Core base colors depending on risk value thresholds
    let bgClass = "bg-[#0b140d] hover:bg-[#122416] border-[#1b3d22]/40"; // Low (1-4)
    let textClass = "text-[#00FF00]/40";
    let accentBorder = "hover:border-[#00FF00]/50";
    let pulseClass = "";

    if (riskVal >= 16) {
      // Critical (16-25): Intense deep crimson purple
      bgClass = count > 0 
        ? "bg-[#330c14] border-[#FF0055]/30 hover:bg-[#4a0f1d]" 
        : "bg-[#1f0a0e] border-[#3d141b] hover:bg-[#2e1016]";
      textClass = count > 0 ? "text-[#FF0055] font-black" : "text-[#FF0055]/30";
      accentBorder = "hover:border-[#FF0055]";
      if (count > 0) pulseClass = "animate-pulse shadow-[inset_0_0_12px_rgba(255,0,85,0.15)]";
    } else if (riskVal >= 9) {
      // High (9-15): Standard warning red/amber
      bgClass = count > 0 
        ? "bg-[#2d1112] border-[#FF3E3E]/30 hover:bg-[#3d1819]" 
        : "bg-[#1c0e0f] border-[#2e1718] hover:bg-[#261314]";
      textClass = count > 0 ? "text-[#FF3E3E] font-extrabold" : "text-[#FF3E3E]/35";
      accentBorder = "hover:border-[#FF3E3E]";
    } else if (riskVal >= 5) {
      // Medium (5-8): Warm Amber/Gold
      bgClass = count > 0 
        ? "bg-[#251809] border-[#F27D26]/30 hover:bg-[#33220c]" 
        : "bg-[#181108] border-[#261b0f] hover:bg-[#21170d]";
      textClass = count > 0 ? "text-[#F27D26] font-bold" : "text-[#F27D26]/35";
      accentBorder = "hover:border-[#F27D26]";
    } else {
      // Low (1-4): Soft emerald
      if (count > 0) {
        bgClass = "bg-[#0c1c11] border-[#00FF00]/30 hover:bg-[#122e1b]";
        textClass = "text-[#00FF00] font-medium";
        accentBorder = "hover:border-[#00FF00]";
      }
    }

    if (isSelected) {
      return {
        classes: `${bgClass} border-2 ${textClass} border-white shadow-[0_0_10px_rgba(255,255,255,0.15)] ring-1 ring-white/20 z-10`,
        countColor: textClass
      };
    }

    return {
      classes: `${bgClass} border ${accentBorder} ${textClass} ${pulseClass}`,
      countColor: count > 0 ? textClass : "text-white/10"
    };
  };

  // Human descriptive labels for matrix indices
  const likelihoodLabels = ["", "Rare", "Unlikely", "Possible", "Likely", "Almost Certain"];
  const impactLabels = ["", "Insignificant", "Minor", "Moderate", "Major", "Severe"];

  // Highest priority finding overall
  const highestRiskFinding = useMemo(() => {
    if (findings.length === 0) return null;
    return [...findings].sort((a, b) => b.riskScore - a.riskScore)[0];
  }, [findings]);

  return (
    <div className="bg-[#111111] border border-[#222222] p-8 mt-8 shadow-none" id="risk-heatmap-module">
      {/* Title Segment */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-[#222] pb-6 mb-6 gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Flame className="w-5 h-5 text-[#FF3E3E] antialiased" />
            <span className="text-[10px] font-bold tracking-[0.2em] text-[#555] uppercase font-mono">Control Prioritization Engine</span>
          </div>
          <h3 className="text-lg font-sans font-black text-white uppercase tracking-wider mt-1.5">Remediation Boundary Risk Heatmap</h3>
          <p className="text-xs text-[#888] mt-1 font-sans">
            Visualizes active infrastructure drift findings mapped directly along the <strong className="text-white">Likelihood (probability)</strong> vs. <strong className="text-white">Impact (blast radius)</strong> axis.
          </p>
        </div>
        
        {/* Quick Reset Option and Info Badge */}
        <div className="flex items-center space-x-3">
          {selectedCoord && (
            <button 
              onClick={() => setSelectedCoord(null)}
              className="flex items-center space-x-1.5 text-xs text-[#888] hover:text-white border border-[#222] bg-[#050505] px-3  py-1.5 font-mono uppercase font-bold transition-all cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
              <span>Clear Filter</span>
            </button>
          )}
          <div className="text-right hidden sm:block bg-[#050505] border border-[#222] px-3 py-1.5 font-mono">
            <span className="text-[10px] text-[#555] uppercase font-bold">Risk Assessment Standard</span>
            <div className="text-xs text-[#DDD] font-bold">MIL-STD-882E Framework</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* Left Grid Section: 5x5 Heatmap Box */}
        <div className="lg:col-span-7 space-y-4">
          
          <div className="relative border border-[#222] bg-[#070707] p-6 lg:p-8 rounded-none">
            {/* Y Axis Description Label */}
            <div className="absolute -left-12 top-1/2 -rotate-90 origin-left -translate-y-1/2 hidden md:flex items-center space-x-1.5">
              <span className="text-[9px] font-mono tracking-[0.25em] text-[#555] uppercase font-bold">Likelihood (probability)</span>
              <ChevronRight className="w-3 h-3 text-[#333] rotate-90" />
            </div>

            {/* Complete 5x5 Matrix Layout */}
            <div className="flex flex-col space-y-1.5">
              {/* Iterating Likelihood from 5 down to 1 */}
              {[5, 4, 3, 2, 1].map(l => {
                return (
                  <div key={`row-${l}`} className="flex items-stretch space-x-1.5">
                    
                    {/* Y-Axis Grid Number Indicator */}
                    <div className="w-10 flex items-center justify-end pr-3.5 text-right font-mono select-none">
                      <span className="text-[10px] font-black text-[#555]">{l}</span>
                    </div>

                    {/* Matrix Cells Loop (Impact 1 to 5) */}
                    {[1, 2, 3, 4, 5].map(i => {
                      const count = gridData[`${l}-${i}`]?.length || 0;
                      const isSelected = selectedCoord ? selectedCoord[0] === l && selectedCoord[1] === i : false;
                      const cellStyles = getCellStyles(l, i, isSelected, count);

                      return (
                        <button
                          key={`cell-${l}-${i}`}
                          onClick={() => {
                            if (isSelected) {
                              setSelectedCoord(null);
                            } else {
                              setSelectedCoord([l, i]);
                            }
                          }}
                          className={`${cellStyles.classes} flex-1 aspect-square md:aspect-auto md:h-20 min-w-0 p-2 flex flex-col justify-between transition-all rounded-none cursor-pointer relative group`}
                          title={`Likelihood Value: ${l} (${likelihoodLabels[l]}), Impact Value: ${i} (${impactLabels[i]}) | Findings: ${count}`}
                        >
                          {/* Top row inside Cell */}
                          <div className="flex items-center justify-between w-full opacity-0 group-hover:opacity-100 transition-opacity">
                            <span className="text-[8px] font-mono text-white/40">{l}x{i}</span>
                            <span className="text-[8px] font-mono font-bold uppercase tracking-tighter text-white/50">{l * i}</span>
                          </div>

                          {/* Center cell visual focal point: Findings count bubble indicator */}
                          <div className="my-auto text-center w-full flex items-center justify-center">
                            {count > 0 ? (
                              <div className="flex flex-col items-center">
                                <span className="text-xl md:text-2xl font-mono font-black tracking-tight leading-none block">{count}</span>
                                <span className="text-[8px] font-mono uppercase tracking-[0.1em] text-white/60 hidden md:block">finding{count > 1 ? "s" : ""}</span>
                              </div>
                            ) : (
                              <span className="text-[9px] font-mono uppercase text-white/5 opacity-20 tracking-wide select-none group-hover:opacity-100 transition-opacity">0</span>
                            )}
                          </div>

                          {/* Active selection dot indicator */}
                          {isSelected && (
                            <div className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-white animate-ping"></div>
                          )}
                        </button>
                      );
                    })}

                  </div>
                );
              })}

              {/* X Axis Grid Number Indicators */}
              <div className="flex items-stretch space-x-1.5 mt-2">
                {/* Empty corner block spacer */}
                <div className="w-10"></div>
                {[1, 2, 3, 4, 5].map(idx => (
                  <div key={`lbl-num-${idx}`} className="flex-1 text-center font-mono py-1 text-[10px] font-bold text-[#555] select-none">
                    {idx}
                  </div>
                ))}
              </div>

              {/* X Axis Word Description Labels */}
              <div className="flex items-stretch space-x-1.5">
                <div className="w-10"></div>
                {["Insignificant", "Minor", "Moderate", "Major", "Severe"].map((text, idx) => (
                  <div key={`lbl-txt-${idx}`} className="flex-1 text-center font-mono text-[8px] text-[#444] uppercase tracking-tighter truncate leading-tight select-none">
                    {text}
                  </div>
                ))}
              </div>

            </div>
          </div>

          {/* Matrix legend */}
          <div className="flex flex-wrap items-center justify-center gap-6 pt-2 text-xs font-mono text-[#777]">
            <div className="flex items-center space-x-2">
              <span className="w-3.5 h-3.5 bg-[#0b140d] border border-[#1b3d22]/40 rounded-none inline-block"></span>
              <span>Low (R: 1-4)</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-3.5 h-3.5 bg-[#251809] border border-[#F27D26]/40 rounded-none inline-block"></span>
              <span>Medium (R: 5-8)</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-3.5 h-3.5 bg-[#2d1112] border border-[#FF3E3E]/40 rounded-none inline-block"></span>
              <span>High (R: 9-15)</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-3.5 h-3.5 bg-[#330c14] border border-[#FF0055]/30 rounded-none inline-block animate-pulse"></span>
              <span>Critical (R: 16-25)</span>
            </div>
          </div>

        </div>

        {/* Right Action Terminal Panel Section: Context Details */}
        <div className="lg:col-span-5 flex flex-col h-full justify-between self-stretch">
          
          <div className="border border-[#222] bg-[#0A0A0A] p-6 flex-1 flex flex-col justify-between h-full select-none">
            <div>
              <div className="flex items-center justify-between border-b border-[#222] pb-4 mb-4">
                <span className="text-[10px] font-mono tracking-widest text-[#555] font-bold uppercase">Target Scan Remediation Queue</span>
                <span className="text-[9px] bg-[#1a1111] text-[#FF3E3E] border border-[#FF3E3E]/3/0 px-2.5 py-0.5 rounded-none font-bold uppercase font-mono">
                  {selectedCoord ? `${filteredFindings.length} selected` : `${activeViolationCount} total`}
                </span>
              </div>

              {/* Displaying selected coordinate filter parameters */}
              {selectedCoord ? (
                <div className="mb-4">
                  <div className="flex items-center justify-between bg-[#111] border border-[#222] p-3 font-mono text-xs">
                    <div>
                      <span className="text-[#888] block text-[9px] uppercase font-bold">Risk Cell Address</span>
                      <span className="text-white font-black">
                        L:{selectedCoord[0]} ({likelihoodLabels[selectedCoord[0]]}) / I:{selectedCoord[1]} ({impactLabels[selectedCoord[1]]})
                      </span>
                    </div>
                    <div className="text-right">
                      <span className="text-[#888] block text-[9px] uppercase font-bold">Severity Value</span>
                      <span className={`font-black ${
                        selectedCoord[0] * selectedCoord[1] >= 16 ? "text-[#FF0055]" : 
                        selectedCoord[0] * selectedCoord[1] >= 9 ? "text-[#FF3E3E]" : 
                        selectedCoord[0] * selectedCoord[1] >= 5 ? "text-[#F27D26]" : "text-[#00FF00]"
                      }`}>
                        R: {selectedCoord[0] * selectedCoord[1]}
                      </span>
                    </div>
                  </div>

                  {filteredFindings.length === 0 ? (
                    <div className="flex flex-col items-center justify-center p-8 bg-[#050505] border border-[#222] text-center min-h-[220px]">
                      <CheckCircle className="w-8 h-8 text-[#00FF00] mb-2.5 opacity-60" />
                      <h4 className="text-white font-bold font-sans text-xs uppercase tracking-wider">Zero Violations Found</h4>
                      <p className="text-[11px] text-[#555] max-w-xs mt-1.5 font-sans leading-relaxed">
                        No policy scan entries are currently mapped along these exact hazard markers. Select another cell parameters grid.
                      </p>
                    </div>
                  ) : (
                    // Findings List under coordinate filter
                    <div className="space-y-3.5 max-h-[340px] overflow-y-auto pr-1">
                      {filteredFindings.map((finding) => (
                        <div key={finding.id} className="bg-[#050505] p-4.5 border border-[#222] hover:border-[#444] transition-all">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="flex items-center space-x-1.5 flex-wrap gap-y-1">
                                <span className={`text-[9px] font-mono px-1.5 py-0.5 border uppercase font-bold ${
                                  finding.severity === "critical" ? "bg-[#330c14] text-[#FF0055] border-[#FF0055]/30" :
                                  finding.severity === "high" ? "bg-[#2d1112] text-[#FF3E3E] border-[#FF3E3E]/30" :
                                  finding.severity === "medium" ? "bg-[#251809] text-[#F27D26] border-[#F27D26]/30" : "bg-[#0c1c11] text-[#00FF00] border-[#00FF00]/30"
                                }`}>
                                  {finding.severity}
                                </span>
                                <span className="text-[10px] font-mono text-white/50">{finding.controlId}</span>
                                <span className="text-[9px] bg-[#111] border border-[#222] text-[#aaa] font-mono px-1.5 font-bold uppercase">{finding.framework}</span>
                              </div>
                              <h4 className="text-white font-mono text-xs font-bold mt-2 leading-relaxed">
                                {finding.finding}
                              </h4>
                              <p className="text-[10px] text-[#555] font-mono mt-1 font-bold">
                                Resource: <span className="text-white/60">{finding.resource}</span>
                              </p>
                            </div>
                          </div>

                          {/* Quick Navigation / Action footer */}
                          <div className="mt-4 pt-3.5 border-t border-[#1C1C1C] flex items-center justify-between">
                            <span className="text-[9px] text-[#444] font-mono uppercase font-bold">L:{finding.likelihood} x I:{finding.impact} = R:{finding.riskScore}</span>
                            <div className="flex items-center space-x-2">
                              {onRemediateFinding && finding.remediation && (
                                <button
                                  onClick={() => onRemediateFinding(finding.remediation, finding.id)}
                                  className="text-[9.5px] bg-[#00FF00]/10 hover:bg-[#00FF00] text-[#00FF00] hover:text-black border border-[#00FF00]/25 px-2.5 py-1 font-mono font-black uppercase tracking-wider transition-all flex items-center space-x-1 shrink-0 cursor-pointer"
                                >
                                  <Zap className="w-2.5 h-2.5" />
                                  <span>Heal Snippet</span>
                                </button>
                              )}
                              <button
                                onClick={() => {
                                  setActiveTab("scan");
                                  setExpandedFinding(finding.id);
                                }}
                                className="text-[9.5px] bg-white hover:bg-[#00FF00] text-black font-mono font-black uppercase tracking-wider px-2.5 py-1 transition-all flex items-center space-x-1 shrink-0 cursor-pointer"
                              >
                                <span>Inspect</span>
                                <ChevronRight className="w-2.5 h-2.5" />
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                </div>
              ) : (
                // Defaults to highest risk summary when nothing is filtered
                <div className="space-y-4">
                  <p className="text-xs text-[#888] font-sans leading-relaxed">
                    Select any cell in the 5x5 hazard coordinate matrix to isolate matching policy violations, investigate infrastructure configurations, or run on-demand closed-loop self-healing snippets instantly.
                  </p>

                  {highestRiskFinding ? (
                    <div className="bg-[#1C1111] border border-[#FF3E3E]/35 p-5">
                      <div className="flex items-center space-x-2">
                        <ShieldAlert className="w-4 h-4 text-[#FF3E3E] shrink-0" />
                        <span className="text-[9px] font-mono font-black bg-[#FF3E3E] text-black px-2 py-0.5 uppercase tracking-wider">Top Priority Hazard Mapping Alert</span>
                      </div>
                      
                      <h4 className="text-white font-mono text-xs font-bold mt-3 leading-relaxed">
                        {highestRiskFinding.finding}
                      </h4>
                      
                      <div className="grid grid-cols-2 gap-3.5 mt-4 text-[10px] font-mono border-t border-[#331113] pt-3 text-[#999]">
                        <div>
                          <span className="text-[#555] block text-[8px] uppercase font-bold">Affected Resource</span>
                          <span className="text-white font-bold truncate block">{highestRiskFinding.resource}</span>
                        </div>
                        <div>
                          <span className="text-[#555] block text-[8px] uppercase font-bold">Standard Standard</span>
                          <span className="text-white font-bold block">{highestRiskFinding.framework} — {highestRiskFinding.controlId}</span>
                        </div>
                        <div>
                          <span className="text-[#555] block text-[8px] uppercase font-bold">Coordinates (L x I x E)</span>
                          <span className="text-white font-bold block">
                            {highestRiskFinding.likelihood} x {highestRiskFinding.impact} x {highestRiskFinding.exposure}
                          </span>
                        </div>
                        <div>
                          <span className="text-[#555] block text-[8px] uppercase font-bold">Raw Risk Score</span>
                          <span className="text-[#FF3E3E] font-black block">R: {highestRiskFinding.riskScore}</span>
                        </div>
                      </div>

                      <div className="mt-4 pt-4 border-t border-[#331113] text-right">
                        <button
                          onClick={() => {
                            setActiveTab("scan");
                            setExpandedFinding(highestRiskFinding.id);
                          }}
                          className="bg-white hover:bg-[#00FF00] text-black text-[10px] px-4 py-2 font-mono font-black uppercase tracking-widest transition-all inline-flex items-center space-x-1 select-none cursor-pointer"
                        >
                          <span>Execute GRC Triage</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center p-8 bg-[#050505] border border-[#222] text-center h-[240px]">
                      <CheckCircle className="w-10 h-10 text-[#00FF00] mb-3 opacity-80" />
                      <h4 className="text-white font-bold font-sans text-xs uppercase tracking-wider">Infrastructure Sealed Compliant</h4>
                      <p className="text-[11px] text-[#555] max-w-xs mt-2 font-sans leading-relaxed">
                        All control lines are fully aligned to SOC2, ISO 27001, and NIST frameworks. No outstanding warnings or risks mapping detected!
                      </p>
                    </div>
                  )}
                </div>
              )}

            </div>

            {/* Micro warning indicator at very bottom */}
            <div className="border-t border-[#222] pt-4 mt-6 flex items-center justify-between text-[9px] font-mono text-[#555]">
              <div className="flex items-center space-x-1.5">
                <Activity className="w-3 h-3 text-[#FF3E3E] shrink-0" />
                <span>REAL-TIME SC_INTEGRITY ACTIVE</span>
              </div>
              <span>COORDINATES ACCURACY: ±0.01%</span>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
