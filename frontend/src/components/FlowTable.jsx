import React, { useMemo } from 'react';
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
import { 
  ChevronLeft, 
  ChevronRight, 
  ChevronsLeft, 
  ChevronsRight,
  Search,
  ArrowUpDown
} from 'lucide-react';

export default function FlowTable({ data }) {
  const [globalFilter, setGlobalFilter] = React.useState('');
  const [sorting, setSorting] = React.useState([]);

  const columns = useMemo(() => [
    {
      accessorKey: 'flow_id',
      header: 'ID',
      cell: info => <span className="mono text-muted-foreground">{info.getValue()}</span>
    },
    {
      accessorKey: 'src_ip',
      header: ({ column }) => (
        <Button variant="ghost" className="h-8 px-2" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
          Source
          <ArrowUpDown className="ml-2 h-4 w-4" />
        </Button>
      ),
      cell: info => <span className="mono font-medium">{info.getValue()}</span>
    },
    {
      accessorKey: 'dst_ip',
      header: ({ column }) => (
        <Button variant="ghost" className="h-8 px-2" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
          Destination
          <ArrowUpDown className="ml-2 h-4 w-4" />
        </Button>
      ),
      cell: info => <span className="mono font-medium">{info.getValue()}</span>
    },
    {
      accessorKey: 'protocol',
      header: 'Proto',
      cell: info => {
        const p = info.getValue();
        return <Badge variant="outline">{p === 6 ? 'TCP' : p === 17 ? 'UDP' : p}</Badge>;
      }
    },
    {
      accessorKey: 'prediction',
      header: 'Prediction',
      cell: ({ row }) => {
        const val = row.original.prediction;
        const confidence = row.original.confidence;
        return (
          <div className="flex items-center gap-2">
            <Badge variant={val.toLowerCase() === 'threat' ? 'threat' : 'benign'}>
              {val}
            </Badge>
            <span className="text-[10px] text-muted-foreground font-mono">{confidence}%</span>
          </div>
        );
      }
    },
    {
      accessorKey: 'sni',
      header: 'SNI / Host',
      cell: info => <span className="mono text-xs max-w-[150px] truncate block">{info.getValue() || '-'}</span>
    }
  ], []);

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
    <div className="space-y-4 animate-fade-in" style={{ animationDelay: '0.2s' }}>
      <div className="flex items-center justify-between">
        <div className="relative w-72">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Filter flows..."
            value={globalFilter ?? ''}
            onChange={e => setGlobalFilter(e.target.value)}
            className="pl-8"
          />
        </div>
        <div className="flex items-center space-x-2 text-sm text-muted-foreground">
          <span>{data.length} Total Flows</span>
        </div>
      </div>

      <div className="rounded-md border bg-card">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map(headerGroup => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map(header => (
                  <TableHead key={header.id}>
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
                <TableRow key={row.id}>
                  {row.getVisibleCells().map(cell => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={columns.length} className="h-24 text-center">
                  No results.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between px-2">
        <div className="flex-1 text-sm text-muted-foreground">
          Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="icon"
            onClick={() => table.setPageIndex(0)}
            disabled={!table.getCanPreviousPage()}
          >
            <ChevronsLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={() => table.setPageIndex(table.getPageCount() - 1)}
            disabled={!table.getCanNextPage()}
          >
            <ChevronsRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
