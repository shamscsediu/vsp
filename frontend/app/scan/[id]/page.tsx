"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import axios from "axios";
import { useParams, useRouter } from "next/navigation";
// Add these imports for PDF generation
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

type Vulnerability = {
  id: number;
  name: string;
  description: string;
  severity: "high" | "medium" | "low" | "info";
  affected_url: string;
  remediation: string;
};

type ScanSummary = {
  total: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

type ScanData = {
  id: number;
  url: string;
  status: "pending" | "in_progress" | "completed" | "failed";
  progress: number;
  current_stage: string;
  vulnerabilities: Vulnerability[];
  summary?: ScanSummary;
};

export default function ScanPage() {
  const params = useParams();
  const router = useRouter();
  const [scanData, setScanData] = useState<ScanData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);

  // Helper function for loading messages - moved to the very top
  const getLoadingMessage = (progress: number) => {
    if (progress < 20) {
      return "Initializing scan and preparing tools...";
    } else if (progress < 40) {
      return "Crawling website and discovering pages...";
    } else if (progress < 60) {
      return "Analyzing site structure and identifying potential vulnerabilities...";
    } else if (progress < 80) {
      return "Running security tests and vulnerability checks...";
    } else {
      return "Finalizing results and generating report...";
    }
  };

  // Add PDF generation function
  const generatePDF = () => {
    if (!scanData) return;
    
    const doc = new jsPDF();
    
    // Add title
    doc.setFontSize(20);
    doc.text("Vulnerability Scan Report", 14, 22);
    
    // Add scan info
    doc.setFontSize(12);
    doc.text(`Target URL: ${scanData.url}`, 14, 32);
    doc.text(`Scan Date: ${new Date().toLocaleDateString()}`, 14, 38);
    doc.text(`Scan ID: ${scanData.id}`, 14, 44);
    
    // Add summary
    if (scanData.summary) {
      doc.setFontSize(16);
      doc.text("Vulnerability Summary", 14, 54);
      
      const summaryData = [
        ["Total", "High", "Medium", "Low", "Info"],
        [
          scanData.summary.total.toString(),
          scanData.summary.high.toString(),
          scanData.summary.medium.toString(),
          scanData.summary.low.toString(),
          scanData.summary.info.toString()
        ]
      ];
      
      autoTable(doc, {
        head: [summaryData[0]],
        body: [summaryData[1]],
        startY: 58,
        headStyles: { fillColor: [66, 66, 66] },
        styles: { halign: 'center' },
        columnStyles: {
          0: { fillColor: [240, 240, 240], textColor: [0, 0, 0] },
          1: { fillColor: [255, 200, 200], textColor: [180, 0, 0] },
          2: { fillColor: [255, 230, 200], textColor: [180, 95, 0] },
          3: { fillColor: [255, 255, 200], textColor: [180, 180, 0] },
          4: { fillColor: [200, 220, 255], textColor: [0, 90, 180] },
        }
      });
    }
    
    // Add vulnerabilities
    if (scanData.vulnerabilities && scanData.vulnerabilities.length > 0) {
      doc.setFontSize(16);
      doc.text("Detailed Vulnerabilities", 14, doc.lastAutoTable ? doc.lastAutoTable.finalY + 15 : 80);
      
      const vulnData = scanData.vulnerabilities.map(vuln => [
        vuln.severity.toUpperCase(),
        vuln.name,
        vuln.description.substring(0, 50) + (vuln.description.length > 50 ? "..." : ""),
        vuln.affected_url
      ]);
      
      autoTable(doc, {
        head: [["Severity", "Name", "Description", "Affected URL"]],
        body: vulnData,
        startY: doc.lastAutoTable ? doc.lastAutoTable.finalY + 20 : 85,
        headStyles: { fillColor: [66, 66, 66] },
        columnStyles: {
          0: { cellWidth: 20 }
        },
        didDrawCell: (data) => {
          if (data.section === 'body' && data.column.index === 0) {
            const severity = scanData.vulnerabilities[data.row.index].severity;
            let fillColor;
            
            switch (severity) {
              case "high":
                fillColor = [255, 200, 200];
                break;
              case "medium":
                fillColor = [255, 230, 200];
                break;
              case "low":
                fillColor = [255, 255, 200];
                break;
              default:
                fillColor = [200, 220, 255];
            }
            
            doc.setFillColor(fillColor[0], fillColor[1], fillColor[2]);
            doc.rect(data.cell.x, data.cell.y, data.cell.width, data.cell.height, 'F');
            doc.setTextColor(0, 0, 0);
            doc.text(
              severity.toUpperCase(),
              data.cell.x + data.cell.width / 2,
              data.cell.y + data.cell.height / 2,
              { align: 'center', baseline: 'middle' }
            );
          }
        }
      });
      
      // Add detailed vulnerability information
      let yPos = doc.lastAutoTable.finalY + 15;
      
      scanData.vulnerabilities.forEach((vuln, index) => {
        // Check if we need a new page
        if (yPos > 250) {
          doc.addPage();
          yPos = 20;
        }
        
        doc.setFontSize(14);
        doc.text(`${index + 1}. ${vuln.name} (${vuln.severity.toUpperCase()})`, 14, yPos);
        yPos += 8;
        
        doc.setFontSize(10);
        doc.text("Description:", 14, yPos);
        yPos += 5;
        
        const descLines = doc.splitTextToSize(vuln.description, 180);
        doc.text(descLines, 14, yPos);
        yPos += descLines.length * 5 + 5;
        
        doc.text("Affected URL:", 14, yPos);
        yPos += 5;
        
        const urlLines = doc.splitTextToSize(vuln.affected_url, 180);
        doc.text(urlLines, 14, yPos);
        yPos += urlLines.length * 5 + 5;
        
        doc.text("Remediation:", 14, yPos);
        yPos += 5;
        
        const remLines = doc.splitTextToSize(vuln.remediation, 180);
        doc.text(remLines, 14, yPos);
        yPos += remLines.length * 5 + 15;
      });
    } else {
      doc.setFontSize(14);
      doc.text("No vulnerabilities were found in this scan.", 14, doc.lastAutoTable ? doc.lastAutoTable.finalY + 15 : 80);
    }
    
    // Add footer
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(10);
      doc.text(
        `Page ${i} of ${pageCount} - Generated by Vulnerability Scanner`,
        doc.internal.pageSize.getWidth() / 2,
        doc.internal.pageSize.getHeight() - 10,
        { align: 'center' }
      );
    }
    
    // Save the PDF
    doc.save(`vulnerability_scan_${scanData.id}.pdf`);
  };

  useEffect(() => {
    const scanId = params.id;
    if (!scanId) return;

    const fetchScanStatus = async () => {
      try {
        const response = await axios.get(`http://localhost:8000/api/scan-status/${scanId}/`);
        setScanData(response.data);

        // If scan is still in progress, poll again after 3 seconds
        if (response.data.status === "pending" || response.data.status === "in_progress") {
          setTimeout(fetchScanStatus, 3000);
        }
      } catch (error) {
        console.error("Error fetching scan status:", error);
        setError("Failed to fetch scan status. Please try again.");
      }
    };

    fetchScanStatus();
  }, [params.id]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "high":
        return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200";
      case "medium":
        return "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200";
      case "low":
        return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200";
      default:
        return "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200";
    }
  };

  const toggleVulnerability = (id: number) => {
    if (expandedVuln === id) {
      setExpandedVuln(null);
    } else {
      setExpandedVuln(id);
    }
  };

  if (error) {
    return (
      <div className="container mx-auto px-4 py-16 flex flex-col items-center justify-center min-h-screen">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 max-w-2xl w-full">
          <h2 className="text-2xl font-bold text-red-600 dark:text-red-400 mb-4">Error</h2>
          <p className="text-gray-700 dark:text-gray-300">{error}</p>
          <button
            onClick={() => router.push("/")}
            className="mt-6 bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-all duration-200"
          >
            Back to Home
          </button>
        </div>
      </div>
    );
  }

  if (!scanData) {
    return (
      <div className="container mx-auto px-4 py-16 flex flex-col items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-lg text-gray-600 dark:text-gray-300">Loading scan data...</p>
        </div>
      </div>
    );
  }

  // Loading screen for in-progress scans
  if (scanData.status === "pending" || scanData.status === "in_progress") {
    return (
      <div className="container mx-auto px-4 py-16 flex flex-col items-center justify-center min-h-screen">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center mb-8"
        >
          <h1 className="text-3xl font-bold mb-2">Scanning {scanData.url}</h1>
          <p className="text-lg text-gray-600 dark:text-gray-300">{scanData.current_stage || "Initializing scan..."}</p>
        </motion.div>

        <div className="w-full max-w-2xl bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8">
          <div className="mb-4">
            <div className="h-2 w-full bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: "0%" }}
                animate={{ width: `${scanData.progress}%` }}
                transition={{ duration: 0.5 }}
                className="h-full bg-gradient-to-r from-blue-600 to-purple-600 rounded-full"
              ></motion.div>
            </div>
            <p className="mt-2 text-right text-sm text-gray-600 dark:text-gray-400">{scanData.progress}%</p>
          </div>

          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
            className="w-24 h-24 border-4 border-blue-600 border-t-transparent rounded-full mx-auto my-8"
          ></motion.div>

          <div className="text-center">
            <p className="text-gray-600 dark:text-gray-300 italic">
              {getLoadingMessage(scanData.progress)}
            </p>
          </div>
        </div>
      </div>
    );
  }

  // Error screen for failed scans
  if (scanData.status === "failed") {
    return (
      <div className="container mx-auto px-4 py-16 flex flex-col items-center justify-center min-h-screen">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 max-w-2xl w-full">
          <h2 className="text-2xl font-bold text-red-600 dark:text-red-400 mb-4">Scan Failed</h2>
          <p className="text-gray-700 dark:text-gray-300">
            We couldn't complete the scan for {scanData.url}. This could be due to network issues, site restrictions, or the site being unavailable.
          </p>
          <button
            onClick={() => router.push("/")}
            className="mt-6 bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-all duration-200"
          >
            Try Another Scan
          </button>
        </div>
      </div>
    );
  }

  // Results screen for completed scans
  return (
    <div className="container mx-auto px-4 py-12">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="mb-8 flex justify-between items-center"
      >
        <div>
          <h1 className="text-3xl font-bold mb-2">Scan Results</h1>
          <p className="text-lg text-gray-600 dark:text-gray-300">
            Target: <span className="font-medium">{scanData.url}</span>
          </p>
        </div>
        <button
          onClick={generatePDF}
          className="bg-purple-600 hover:bg-purple-700 text-white font-medium py-2 px-6 rounded-lg transition-all duration-200 flex items-center"
        >
          <svg 
            className="w-5 h-5 mr-2" 
            fill="none" 
            stroke="currentColor" 
            viewBox="0 0 24 24" 
            xmlns="http://www.w3.org/2000/svg"
          >
            <path 
              strokeLinecap="round" 
              strokeLinejoin="round" 
              strokeWidth={2} 
              d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" 
            />
          </svg>
          Download Report
        </button>
      </motion.div>

      {scanData.summary && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 mb-8"
        >
          <h2 className="text-xl font-semibold mb-4">Vulnerability Summary</h2>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-gray-100 dark:bg-gray-700 p-4 rounded-lg text-center">
              <p className="text-2xl font-bold">{scanData.summary.total}</p>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total</p>
            </div>
            <div className="bg-red-50 dark:bg-red-900/30 p-4 rounded-lg text-center">
              <p className="text-2xl font-bold text-red-600 dark:text-red-400">{scanData.summary.high}</p>
              <p className="text-sm text-red-600 dark:text-red-400">High</p>
            </div>
            <div className="bg-orange-50 dark:bg-orange-900/30 p-4 rounded-lg text-center">
              <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">{scanData.summary.medium}</p>
              <p className="text-sm text-orange-600 dark:text-orange-400">Medium</p>
            </div>
            <div className="bg-yellow-50 dark:bg-yellow-900/30 p-4 rounded-lg text-center">
              <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{scanData.summary.low}</p>
              <p className="text-sm text-yellow-600 dark:text-yellow-400">Low</p>
            </div>
            <div className="bg-blue-50 dark:bg-blue-900/30 p-4 rounded-lg text-center">
              <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">{scanData.summary.info}</p>
              <p className="text-sm text-blue-600 dark:text-blue-400">Info</p>
            </div>
          </div>
        </motion.div>
      )}

      <div className="space-y-4">
        {scanData.vulnerabilities && scanData.vulnerabilities.length > 0 ? (
          scanData.vulnerabilities.map((vuln, index) => (
            <motion.div
              key={vuln.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 + index * 0.1 }}
              className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden"
            >
              <div
                className="p-6 cursor-pointer"
                onClick={() => toggleVulnerability(vuln.id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity.toUpperCase()}
                    </span>
                    <h3 className="text-lg font-semibold">{vuln.name}</h3>
                  </div>
                  <svg
                    className={`w-5 h-5 transition-transform ${expandedVuln === vuln.id ? 'transform rotate-180' : ''}`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>

              {expandedVuln === vuln.id && (
                <div className="px-6 pb-6 pt-2 border-t border-gray-200 dark:border-gray-700">
                  <div className="mb-4">
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">Description</h4>
                    <p className="text-gray-700 dark:text-gray-300">{vuln.description}</p>
                  </div>
                  <div className="mb-4">
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">Affected URL</h4>
                    <p className="text-blue-600 dark:text-blue-400 break-all">{vuln.affected_url}</p>
                  </div>
                  <div>
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">Remediation</h4>
                    <p className="text-gray-700 dark:text-gray-300">{vuln.remediation}</p>
                  </div>
                </div>
              )}
            </motion.div>
          ))
        ) : (
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 text-center">
            <h3 className="text-xl font-semibold mb-2">No vulnerabilities found</h3>
            <p className="text-gray-600 dark:text-gray-400">
              Great news! We didn't detect any vulnerabilities on this website. However, this doesn't guarantee the site is completely secure.
            </p>
          </div>
        )}
      </div>

      <div className="mt-8 text-center">
        <button
          onClick={() => router.push("/")}
          className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-6 rounded-lg transition-all duration-200"
        >
          Scan Another Website
        </button>
      </div>
    </div>
  );
}