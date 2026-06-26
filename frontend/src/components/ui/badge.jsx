import { cn } from "@/lib/utils"

export function Badge({ className, variant = "default", ...props }) {
  const variants = {
    default:     "bg-secondary text-secondary-foreground",
    threat:      "badge-threat",
    benign:      "badge-benign",
    outline:     "border border-border text-foreground",
    muted:       "bg-muted text-muted-foreground",
  }
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium font-mono",
        variants[variant],
        className
      )}
      {...props}
    />
  )
}
