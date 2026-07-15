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
  ArrowUpDown, Filter, Eye, RefreshCw, X, ShieldAlert, Cpu
} from 'lucide-react';

export default function FlowExplorer({ data, apiEndpoint, onRefresh }) {
  const [globalFilter, setGlobalFilter] = useState('');
  const [sorting, setSorting] = useState([]);
  const [selectedFlowId, setSelectedFlowId] = useState(null);
  const [flowDetails, setFlowDetails] = useState(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

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

  const columns = useMemo(() => [
    {
      accessorKey: 'flow_id',
      header: 'Flow ID',
      cell: info => <span className="mono text-muted-foreground">{info.getValue()?.substring(0, 8)}...</span>
    },
    {
      accessorKey: 'src_ip',
      header: ({ column }) => (
        <Button variant="ghost" className="h-8 px-2 uppercase mono text-[9px] font-bold" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
          Source
          <ArrowUpDown className="ml-1.5 h-3 w-3" />
        </Button>
      ),
      cell: info => <span className="mono font-medium">{info.getValue()}:{info.row.original.src_port}</span>
    },
    {
      accessorKey: 'dst_ip',
      header: ({ column }) => (
        <Button variant="ghost" className="h-8 px-2 uppercase mono text-[9px] font-bold" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
          Destination
          <ArrowUpDown className="ml-1.5 h-3 w-3" />
        </Button>
      ),
      cell: info => <span className="mono font-medium">{info.getValue()}:{info.row.original.dst_port}</span>
    },
    {
      accessorKey: 'protocol',
      header: 'Proto',
      cell: info => <Badge variant="outline">{info.getValue()}</Badge>
    },
    {
      accessorKey: 'prediction',
      header: 'Classification',
      cell: ({ row }) => {
        const val = row.original.prediction;
        const confidence = row.original.confidence;
        return (
          <div className="flex items-center gap-2">
            <Badge variant={val.toLowerCase() === 'threat' ? 'threat' : 'benign'}>
              {val}
            </Badge>
            <span className="text-[9px] text-muted-foreground font-mono">{confidence}%</span>
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
        const val = info.getValue();
        const isThreat = info.row.original.prediction === 'Threat';
        return <span className={isThreat ? 'text-threat font-bold mono' : 'text-benign mono'}>{val}</span>;
      }
    },
    {
      accessorKey: 'sni',
      header: 'SNI Hostname',
      cell: info => <span className="mono text-[10px] max-w-[140px] truncate block text-primary">{info.getValue() || '-'}</span>
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: ({ row }) => (
        <Button size="icon" variant="ghost" className="h-7 w-7 text-muted-foreground hover:text-white" onClick={() => fetchFlowDetail(row.original.flow_id)}>
          <Eye className="w-3.5 h-3.5" />
        </Button>
      )
    }
  ], [apiEndpoint]);

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
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 border-b border-white/5 pb-6">
        <div>
          <h2 className="text-2xl font-black tracking-tight text-white uppercase italic">Forensic Flow Explorer</h2>
          <p className="text-[10px] text-muted-foreground uppercase mono tracking-[0.15em] mt-1">
            Browse, sort, and query historical session connections in database
          </p>
        </div>
        {onRefresh && (
          <Button onClick={onRefresh} variant="outline" className="border-white/10 hover:bg-white/5 uppercase mono text-[9px] font-bold">
            <RefreshCw className="w-3 mr-2" /> Sync Flow Records
          </Button>
        )}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Table list: 8 cols */}
        <Card className="xl:col-span-8 p-6 border border-white/5 bg-black/40 space-y-4">
          <div className="flex items-center justify-between">
            <div className="relative w-80">
              <Search className="absolute left-2.5 top-3.5 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Query flows (IP, SNI)..."
                value={globalFilter ?? ''}
                onChange={e => setGlobalFilter(e.target.value)}
                className="pl-8 bg-white/5 border-white/10 text-xs text-slate-200 focus-visible:ring-primary/30"
              />
            </div>
            <div className="text-[10px] mono text-muted-foreground uppercase">
              {data.length} records retrieved
            </div>
          </div>

          <div className="rounded-xl border border-white/5 bg-black/20 overflow-hidden">
            <Table>
              <TableHeader className="bg-white/[0.01] border-b border-white/5">
                {table.getHeaderGroups().map(headerGroup => (
                  <TableRow key={headerGroup.id} className="border-b border-white/5 hover:bg-transparent">
                    {headerGroup.headers.map(header => (
                      <TableHead key={header.id} className="text-muted-foreground uppercase text-[9px] tracking-wider py-3">
                        {header.isPlaceholder
                          ? null
                          : flexRender(header.column.columnDef.header, header.getContext())}
                      </TableHead>
                    ))}
                  </TableRow>
                ))}
              </TableHeader>
              <TableBody>
                {table.getRowModel().rows?.length ? (
                  table.getRowModel().rows.map(row => (
                    <TableRow key={row.id} className="border-b border-white/5 hover:bg-white/[0.01]">
                      {row.getVisibleCells().map(cell => (
                        <TableCell key={cell.id} className="py-2.5">
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={columns.length} className="h-28 text-center text-[10px] mono text-muted-foreground uppercase">
                      No flow records found.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>

          {/* Pagination controls */}
          <div className="flex items-center justify-between text-xs text-muted-foreground pt-2">
            <div>
              Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
            </div>
            <div className="flex items-center space-x-2">
              <Button variant="outline" size="icon" onClick={() => table.setPageIndex(0)} disabled={!table.getCanPreviousPage()} className="h-7 w-7 border-white/10 hover:bg-white/5">
                <ChevronsLeft className="h-4 w-4" />
              </Button>
              <Button variant="outline" size="icon" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()} className="h-7 w-7 border-white/10 hover:bg-white/5">
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <Button variant="outline" size="icon" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()} className="h-7 w-7 border-white/10 hover:bg-white/5">
                <ChevronRight className="h-4 w-4" />
              </Button>
              <Button variant="outline" size="icon" onClick={() => table.setPageIndex(table.getPageCount() - 1)} disabled={!table.getCanNextPage()} className="h-7 w-7 border-white/10 hover:bg-white/5">
                <ChevronsRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </Card>

        {/* Drill down inspector side panel: 4 cols */}
        <Card className="xl:col-span-4 p-6 border border-white/5 bg-gradient-to-br from-card/20 to-transparent min-h-[500px]">
          {selectedFlowId ? (
            loadingDetails ? (
              <div className="h-full flex flex-col items-center justify-center py-40 space-y-3">
                <Loader2 className="w-6 h-6 text-primary animate-spin" />
                <span className="text-[10px] mono uppercase tracking-wider text-muted-foreground">Gathering diagnostic data...</span>
              </div>
            ) : flowDetails ? (
              <div className="space-y-6 animate-fade-in">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Filter className="w-4 h-4 text-primary" />
                    <span className="text-[9px] mono uppercase font-bold text-muted-foreground tracking-widest">Flow Inspector</span>
                  </div>
                  <Button size="icon" variant="ghost" onClick={() => setSelectedFlowId(null)} className="h-7 w-7 text-muted-foreground hover:text-white">
                    <X className="w-4.5 h-4.5" />
                  </Button>
                </div>

                <div>
                  <Badge variant={flowDetails.prediction === 'Threat' ? 'threat' : 'benign'} className="mb-2">
                    {flowDetails.severity || 'Benign'} Flow
                  </Badge>
                  <h3 className="text-[11px] font-black text-white mono truncate">{flowDetails.flow_id}</h3>
                </div>

                <Separator className="bg-white/5" />

                <div className="space-y-3 text-[10px] mono">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Source IP:</span>
                    <span>{flowDetails.src_ip}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Destination IP:</span>
                    <span>{flowDetails.dst_ip}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">SNI Host:</span>
                    <span className="text-primary truncate max-w-[160px]">{flowDetails.sni || '-'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">TCP Flags:</span>
                    <span className="text-slate-300 font-bold">{flowDetails.tcp_flags || 'UDP'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Duration:</span>
                    <span>{flowDetails.flow_duration?.toFixed(3)}s</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Total Bytes:</span>
                    <span>{flowDetails.bytes_sent + flowDetails.bytes_received} B</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Packets:</span>
                    <span>{flowDetails.total_packets} ({flowDetails.total_fwd_packets} fwd / {flowDetails.total_bwd_packets} bwd)</span>
                  </div>
                </div>

                {flowDetails.prediction === 'Threat' && (
                  <>
                    <Separator className="bg-white/5" />
                    <div className="p-3 border border-red-500/20 bg-red-500/[0.02] rounded-lg text-[10px] mono text-threat leading-tight">
                      <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider mb-1">
                        <ShieldAlert className="w-3.5 h-3.5" /> Threat Indicators Detected
                      </div>
                      <p className="opacity-90">Model Confidence: <b>{flowDetails.confidence}%</b></p>
                      <p className="opacity-90 mt-1">Reputation Score: <b>{Math.max(flowDetails.ip_reputation_score || 0, flowDetails.domain_reputation_score || 0)}%</b></p>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="text-center py-20 text-[10px] text-muted-foreground mono uppercase">
                 Failed to load flow.
              </div>
            )
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center text-muted-foreground py-20">
              <Eye className="w-8 h-8 text-muted-foreground/20 mb-3" />
              <p className="text-[10px] uppercase mono tracking-widest leading-loose">Click detail view icon on a flow to inspect details</p>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
