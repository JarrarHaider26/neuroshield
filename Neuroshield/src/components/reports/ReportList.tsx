
'use client';

import type { ScanFileOutput } from "@/ai/flows/scan-file-flow";
import type { ScanUrlOutput } from "@/ai/flows/scan-url-flow";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Download, FileUp, Link as LinkIcon, FileText as DefaultIcon, FileType, FileText, User, Trash2 } from 'lucide-react';
import { generateScanReportDocx, generateScanReportPdf } from "@/lib/report-generator";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"

export interface SavedReport {
  id: string;
  userId: string;
  scanType: 'file' | 'url';
  targetIdentifier: string;
  scanDate: Date;
  status: string;
  threatLabel: string | null;
  analysisId: string;
  permalink: string | null;
  reportData: ScanFileOutput | ScanUrlOutput;
  createdAt: Date;
}

interface UserMap {
  [key: string]: {
    email: string;
    displayName: string;
  }
}

interface ReportListProps {
  reports: SavedReport[];
  userMap?: UserMap;
  isAdminView?: boolean;
  onDeleteReport?: (report: SavedReport) => void;
}

const getThreatLevelBadgeVariant = (level: string | null) => {
  if (!level) return 'outline';
  switch (level.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'destructive';
    case 'medium':
      return 'secondary';
    case 'low':
    case 'clean':
    case 'none':
      return 'default';
    default:
      return 'outline';
  }
};

const getStatusBadgeVariant = (status: string) => {
    switch (status.toLowerCase()) {
        case 'completed':
            return 'default';
        case 'queued':
        case 'inprogress':
            return 'secondary';
        case 'error':
            return 'destructive';
        default:
            return 'outline';
    }
}

export function ReportList({ reports, userMap, isAdminView = false, onDeleteReport }: ReportListProps) {

  const handleDownloadDocx = async (report: SavedReport) => {
    await generateScanReportDocx(report.reportData, report.scanType);
  };
  
  const handleDownloadPdf = async (report: SavedReport) => {
    await generateScanReportPdf(report.reportData, report.scanType);
  };

  if (reports.length === 0) {
    return (
      <div className="text-center py-16 text-muted-foreground">
        <DefaultIcon className="mx-auto h-16 w-16 mb-6" />
        <h3 className="text-xl font-semibold mb-2">No Reports Found</h3>
        <p>Your scan reports will appear here once you analyze files or URLs.</p>
        <p className="text-sm mt-1">Adjust filters or perform a new scan if you expect to see reports.</p>
      </div>
    );
  }

  return (
    <TooltipProvider>
      <Table>
        <TableCaption className="py-4">A list of scan reports. ({reports.length} found)</TableCaption>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-[60px] text-center">Type</TableHead>
            <TableHead>Target</TableHead>
            {isAdminView && <TableHead className="hidden lg:table-cell">User</TableHead>}
            <TableHead className="hidden sm:table-cell">Status</TableHead>
            <TableHead>Threat Level</TableHead>
            <TableHead className="text-right w-[100px]">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {reports.map((report) => {
            const IconComponent = report.scanType === 'file' ? FileUp : LinkIcon;
            const threatColorClass =
                report.threatLabel === 'High' || report.threatLabel === 'Critical' ? 'text-destructive'
                : report.threatLabel === 'Medium' ? 'text-yellow-500'
                : report.threatLabel === 'Low' || report.threatLabel === 'Clean' || report.threatLabel === 'None' ? 'text-green-500'
                : 'text-primary';
            const userDetails = userMap && report.userId ? userMap[report.userId] : null;
            return (
            <TableRow key={report.id} className="hover:bg-muted/50">
              <TableCell className="text-center">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <IconComponent className={`h-5 w-5 ${threatColorClass} mx-auto`} />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{report.scanType === 'file' ? 'File Scan' : 'URL Scan'}</p>
                  </TooltipContent>
                </Tooltip>
              </TableCell>
              <TableCell className="font-medium truncate max-w-[120px] sm:max-w-[150px] md:max-w-[200px] text-foreground" title={report.targetIdentifier}>
                {report.targetIdentifier}
              </TableCell>
              {isAdminView && (
                <TableCell className="hidden lg:table-cell text-muted-foreground truncate max-w-[150px]">
                   <Tooltip>
                    <TooltipTrigger>
                      <div className="flex items-center gap-2">
                          <User className="h-4 w-4 shrink-0" />
                          <span className="truncate">{userDetails?.displayName || 'Unknown User'}</span>
                      </div>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>{userDetails?.displayName}</p>
                      <p className="text-xs">{userDetails?.email}</p>
                    </TooltipContent>
                  </Tooltip>
                </TableCell>
              )}
              <TableCell className="hidden sm:table-cell">
                <Badge variant={getStatusBadgeVariant(report.status)}
                      className={
                          report.status.toLowerCase() === 'completed' ? 'bg-green-600/20 text-green-400 border-green-600/30' :
                          report.status.toLowerCase() === 'error' ? '' : // destructive variant handles this
                          (report.status.toLowerCase() === 'queued' || report.status.toLowerCase() === 'inprogress') ? 'bg-yellow-600/20 text-yellow-400 border-yellow-600/30' :
                          ''
                      }>
                  {report.status}
                </Badge>
              </TableCell>
              <TableCell>
                <Badge variant={getThreatLevelBadgeVariant(report.threatLabel)}
                      className={
                          !report.threatLabel || report.threatLabel.toLowerCase() === 'unknown' ? 'opacity-70' :
                          report.threatLabel.toLowerCase() === 'critical' ? 'bg-red-600/20 text-red-400 border-red-600/40 font-semibold' :
                          report.threatLabel.toLowerCase() === 'high' ? 'bg-orange-600/20 text-orange-400 border-orange-600/40' :
                          report.threatLabel.toLowerCase() === 'medium' ? 'bg-yellow-600/20 text-yellow-400 border-yellow-600/40' :
                          report.threatLabel.toLowerCase() === 'low' ? 'bg-blue-600/20 text-blue-400 border-blue-600/40' :
                          report.threatLabel.toLowerCase() === 'none' || report.threatLabel.toLowerCase() === 'clean' ? 'bg-green-600/20 text-green-400 border-green-600/40' :
                          ''
                      }>
                  {report.threatLabel || 'N/A'}
                </Badge>
              </TableCell>
              <TableCell className="text-right">
                <div className="flex gap-1 justify-end items-center">
                  <DropdownMenu>
                    <Tooltip>
                        <TooltipTrigger asChild>
                            <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="hover:text-primary">
                                    <Download className="h-4 w-4" />
                                </Button>
                            </DropdownMenuTrigger>
                        </TooltipTrigger>
                        <TooltipContent><p>Download Report</p></TooltipContent>
                    </Tooltip>
                    <DropdownMenuContent>
                        <DropdownMenuItem onClick={() => handleDownloadDocx(report)}>
                            <FileText className="mr-2 h-4 w-4" />
                            <span>Download as DOCX</span>
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleDownloadPdf(report)}>
                            <FileType className="mr-2 h-4 w-4" />
                            <span>Download as PDF</span>
                        </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>

                  {onDeleteReport && (
                    <Tooltip>
                        <TooltipTrigger asChild>
                            <Button variant="ghost" size="icon" className="hover:text-destructive" onClick={() => onDeleteReport(report)}>
                                <Trash2 className="h-4 w-4" />
                            </Button>
                        </TooltipTrigger>
                        <TooltipContent><p>Delete Report</p></TooltipContent>
                    </Tooltip>
                  )}
                </div>
              </TableCell>
            </TableRow>
          )})}
        </TableBody>
      </Table>
    </TooltipProvider>
  );
}
