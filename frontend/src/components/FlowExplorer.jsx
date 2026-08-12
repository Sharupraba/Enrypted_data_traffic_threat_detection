import React, { useMemo, useState } from 'react';
import { 
  useReactTable, 
  getCoreRowModel, 
  getPaginationRowModel, 
  getFilteredRowModel, 
  getSortedRowModel, 
  flexRender 
} from '@tanstack/react-table';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from './ui/table';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Card } from './ui/card';
import { Separator } from './ui/separator';
import { 
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Search, 
  ArrowUpDown, Filter, Eye, RefreshCw, X, ShieldAlert, Cpu, Loader2, ShieldCheck
} from 'lucide-react';

export default function FlowExplorer({ data, apiEndpoint, onRefresh }) {
  const [globalFilter, setGlobalFilter] = useState('');
  const [sorting, setSorting] = useState([]);
  const [selectedFlowId, setSelectedFlowId] = useState(null);
  const [flowDetails, setFlowDetails] = useState(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [allowLoading, setAllowLoading] = useState(false);

  const fetchFlowDetail = async (flowId) => {
    setSelectedFlowId(flowId);
    setLoadingDetails(true);
    setFlowDetails(null);
    try {
      const response = await fetch(`${apiEndpoint}/api/flows/${flowId}`);
      if (response.ok) {
        const detail = await response.json();
        setFlowDetails(detail);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingDetails(false);
    }
  };

  const handleAllowFlow = async (e, flowId) => {
    if (e) e.stopPropagation();
    setAllowLoading(true);
    try {
      const response = await fetch(`${apiEndpoint}/api/flows/${flowId}/allow`, {
        method: 'POST'
      });
      if (response.ok) {
        setSelectedFlowId(null);
        if (onRefresh) await onRefresh();
      }
    } catch (err) {
      console.error("Failed to allow flow:", err);
    } finally {
      setAllowLoading(false);
    }
  };

  const columns = useMemo(() => [
    {
      accessorKey: 'flow_id',
      header: 'Flow ID',
      cell: info => <span className="mono text-slate-500">{info.getValue()?.substring(0, 8)}...</span>
    },
    {
      accessorKey: 'src_ip',
      header: ({ column }) => (
        <Button variant="ghost" className="h-8 px-2 uppercase mono text-[9px] font-bold" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
          Source
          <ArrowUpDown className="ml-1.5 h-3 w-3" />
        </Button>
      ),
      cell: info => <span className="mono font-semibold text-slate-800">{info.getValue()}:{info.row.original.src_port}</span>
    },
    {
      accessorKey: 'dst_ip',
      header: ({ column }) => (
        <Button variant="ghost" className="h-8 px-2 uppercase mono text-[9px] font-bold" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
          Destination
          <ArrowUpDown className="ml-1.5 h-3 w-3" />
        </Button>
      ),
      cell: info => <span className="mono font-semibold text-slate-800">{info.getValue()}:{info.row.original.dst_port}</span>
    },
    {
      accessorKey: 'protocol',
      header: 'Proto',
      cell: info => <Badge variant="outline" className="bg-white border-slate-200 text-slate-700">{info.getValue()}</Badge>
    },
    {
      accessorKey: 'classification',
      header: 'Classification',
      cell: ({ row }) => {
        const val = row.original.classification || 'Benign';
        const confidence = row.original.confidence || 100;
        return (
          <div className="flex items-center gap-2">
            <Badge variant={val.toLowerCase() === 'threat' ? 'threat' : 'benign'}>
              {val}
            </Badge>
            <span className="text-[9px] text-slate-500 font-mono">{confidence}%</span>
          </div>
        );
      }
    },
    {
      accessorKey: 'risk_score',
      header: ({ column }) => (
        <Button variant="ghost" className="h-8 px-2 uppercase mono text-[9px] font-bold" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
          Risk
          <ArrowUpDown className="ml-1.5 h-3 w-3" />
        </Button>
      ),
      cell: info => {
        const val = info.getValue() || 0;
        const isThreat = (info.row.original.classification || 'Benign') === 'Threat';
        return <span className={isThreat ? 'text-red-600 font-bold mono' : 'text-emerald-600 font-medium mono'}>{val}</span>;
      }
    },
    {
      accessorKey: 'sni',
      header: 'SNI Hostname',
      cell: info => <span className="mono text-[10px] max-w-[140px] truncate block text-indigo-600 font-medium">{info.getValue() || '-'}</span>
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: ({ row }) => {
        const isThreat = (row.original.classification || 'Benign') === 'Threat';
        return (
          <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
            <Button 
              size="sm" 
              variant="outline" 
              className="h-7 px-2.5 text-[10px] border-slate-200 bg-white hover:bg-slate-50 text-slate-700"
              onClick={() => fetchFlowDetail(row.original.flow_id)}
            >
              Inspect
            </Button>
            {isThreat && (
              <Button 
                size="sm" 
                className="h-7 px-2.5 text-[10px] bg-emerald-600 hover:bg-emerald-700 text-white font-medium"
                onClick={(e) => handleAllowFlow(e, row.original.flow_id)}
                disabled={allowLoading}
              >
                Allow
              </Button>
            )}
          </div>
        );
      }
    }
  ], [apiEndpoint, allowLoading]);

  const table = useReactTable({
    data,
    columns,
    state: {
      globalFilter,
      sorting,
    },
    onGlobalFilterChange: setGlobalFilter,
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    initialState: {
      pagination: {
        pageSize: 10,
      },
    },
  });

  return (
    <div className="space-y-6 relative">
      {/* Header controls panel */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 border-b border-slate-200 pb-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900">Forensic Flow Explorer</h2>
          <p className="text-xs text-slate-500 mt-1">
            Browse, sort, and query historical session connections in database
          </p>
        </div>
        {onRefresh && (
          <Button onClick={onRefresh} variant="outline" className="border-slate-200 bg-white hover:bg-slate-50 text-xs font-medium">
            <RefreshCw className="w-3 mr-2 text-slate-500" /> Sync Flow Records
          </Button>
        )}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Table list: 8 cols */}
        <Card className="xl:col-span-8 p-6 border border-slate-200 bg-white space-y-4 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="relative w-80">
              <Search className="absolute left-2.5 top-3 h-4 w-4 text-slate-400" />
              <Input
                placeholder="Query flows (IP, SNI)..."
                value={globalFilter ?? ''}
                onChange={e => setGlobalFilter(e.target.value)}
                className="pl-9 bg-white border-slate-200 text-xs text-slate-800 focus-visible:ring-slate-300"
              />
            </div>
            <div className="text-[10px] mono text-slate-500 uppercase">
              {data.length} records retrieved
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-slate-50/30 overflow-hidden">
            <Table>
              <TableHeader className="bg-slate-50 border-b border-slate-200">
                {table.getHeaderGroups().map(headerGroup => (
                  <TableRow key={headerGroup.id} className="border-b border-slate-200 hover:bg-transparent">
                    {headerGroup.headers.map(header => (
                      <TableHead key={header.id} className="text-slate-500 uppercase text-[9px] tracking-wider py-3 font-semibold">
                        {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                      </TableHead>
                    ))}
                  </TableRow>
                ))}
              </TableHeader>
              <TableBody>
                {table.getRowModel().rows?.length ? (
                  table.getRowModel().rows.map(row => (
                    <TableRow 
                      key={row.id} 
                      className="border-b border-slate-100 hover:bg-slate-50/50 cursor-pointer"
                      onClick={() => fetchFlowDetail(row.original.flow_id)}
                    >
                      {row.getVisibleCells().map(cell => (
                        <TableCell key={cell.id} className="py-2.5">
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={columns.length} className="h-28 text-center text-xs text-slate-400 uppercase tracking-wider font-medium">
                      No flow records found.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>

          {/* Pagination controls */}
          <div className="flex items-center justify-between text-xs text-slate-500 pt-2">
            <div>
              Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
            </div>
            <div className="flex items-center space-x-2">
              <Button variant="outline" size="icon" onClick={() => table.setPageIndex(0)} disabled={!table.getCanPreviousPage()} className="h-7 w-7 border-slate-200 hover:bg-slate-50 bg-white">
                <ChevronsLeft className="h-4 w-4 text-slate-500" />
              </Button>
              <Button variant="outline" size="icon" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()} className="h-7 w-7 border-slate-200 hover:bg-slate-50 bg-white">
                <ChevronLeft className="h-4 w-4 text-slate-500" />
              </Button>
              <Button variant="outline" size="icon" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()} className="h-7 w-7 border-slate-200 hover:bg-slate-50 bg-white">
                <ChevronRight className="h-4 w-4 text-slate-500" />
              </Button>
              <Button variant="outline" size="icon" onClick={() => table.setPageIndex(table.getPageCount() - 1)} disabled={!table.getCanNextPage()} className="h-7 w-7 border-slate-200 hover:bg-slate-50 bg-white">
                <ChevronsRight className="h-4 w-4 text-slate-500" />
              </Button>
            </div>
          </div>
        </Card>

        {/* Drill down inspector side panel: 4 cols */}
        <Card className="xl:col-span-4 p-6 border border-slate-200 bg-white min-h-[500px] shadow-sm">
          {selectedFlowId ? (
            loadingDetails ? (
              <div className="h-full flex flex-col items-center justify-center py-40 space-y-3">
                <Loader2 className="w-6 h-6 text-slate-800 animate-spin" />
                <span className="text-xs text-slate-400">Gathering diagnostic data...</span>
              </div>
            ) : flowDetails ? (
              <div className="space-y-6 animate-fade-in">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Filter className="w-4 h-4 text-slate-700" />
                    <span className="text-[9px] mono uppercase font-bold text-slate-500 tracking-widest">Flow Inspector</span>
                  </div>
                  <Button size="icon" variant="ghost" onClick={() => setSelectedFlowId(null)} className="h-7 w-7 text-slate-400 hover:text-slate-800">
                    <X className="w-4.5 h-4.5" />
                  </Button>
                </div>

                <div>
                  <Badge variant={(flowDetails.classification || 'Benign').toLowerCase() === 'threat' ? 'threat' : 'benign'} className="mb-2">
                    {flowDetails.severity || 'Benign'} Flow
                  </Badge>
                  <h3 className="text-xs font-bold text-slate-900 mono truncate">{flowDetails.flow_id}</h3>
                </div>

                <Separator className="bg-slate-200" />

                <div className="space-y-3 text-[10px] mono">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Source IP:</span>
                    <span className="text-slate-800 font-semibold">{flowDetails.src_ip}:{flowDetails.src_port}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Destination IP:</span>
                    <span className="text-slate-800 font-semibold">{flowDetails.dst_ip}:{flowDetails.dst_port}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">SNI Host:</span>
                    <span className="text-indigo-600 font-semibold truncate max-w-[160px]">{flowDetails.sni || '-'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Protocol Details:</span>
                    <span className="text-slate-800 font-bold">
                      {flowDetails.protocol === 17 || flowDetails.protocol === 'UDP' ? 'UDP' : (
                        [
                          flowDetails.syn_count > 0 && 'SYN',
                          flowDetails.ack_count > 0 && 'ACK',
                          flowDetails.rst_count > 0 && 'RST',
                          flowDetails.fin_count > 0 && 'FIN',
                          flowDetails.psh_count > 0 && 'PSH'
                        ].filter(Boolean).join(' | ') || 'TCP'
                      )}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Duration:</span>
                    <span className="text-slate-800">{flowDetails.flow_duration?.toFixed(3)}s</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Total Bytes:</span>
                    <span className="text-slate-800">{flowDetails.bytes_sent + flowDetails.bytes_received} B</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Packets:</span>
                    <span className="text-slate-800">{flowDetails.total_packets} ({flowDetails.total_fwd_packets} fwd / {flowDetails.total_bwd_packets} bwd)</span>
                  </div>
                </div>

                {(flowDetails.classification || 'Benign') === 'Threat' ? (
                  <>
                    <Separator className="bg-slate-200" />
                    <div className="p-3 border border-red-200 bg-red-50/40 rounded-lg text-[10px] mono text-red-700 leading-tight space-y-1.5">
                      <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider">
                        <ShieldAlert className="w-3.5 h-3.5 text-red-600" /> Threat Indicators Detected
                      </div>
                      <p className="opacity-90">Model Confidence: <b>{flowDetails.confidence}%</b></p>
                      <p className="opacity-90">Reputation Score: <b>{Math.max(flowDetails.ip_reputation_score || 0, flowDetails.domain_reputation_score || 0)}%</b></p>
                    </div>
                    <Button 
                      onClick={(e) => handleAllowFlow(e, flowDetails.flow_id)}
                      disabled={allowLoading}
                      className="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-medium text-xs gap-1.5"
                    >
                      <ShieldCheck className="w-4 h-4" /> Allow & Whitelist Connection
                    </Button>
                  </>
                ) : (
                  <>
                    <Separator className="bg-slate-200" />
                    <div className="p-3 border border-emerald-200 bg-emerald-50/40 rounded-lg text-[10px] mono text-emerald-700 leading-tight flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4" /> Allowed Connection (Safe)
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="text-center py-20 text-xs text-slate-400">
                 Failed to load flow.
              </div>
            )
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center text-slate-400 py-20">
              <Eye className="w-8 h-8 text-slate-300 mb-3" />
              <p className="text-xs font-medium tracking-normal leading-loose">Select a flow to inspect dynamic forensic telemetry</p>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
