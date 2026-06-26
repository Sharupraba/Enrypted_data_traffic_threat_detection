import React, { forwardRef } from "react"
import { cn } from "@/lib/utils"

const Button = forwardRef(({ className, variant = "default", size = "default", ...props }, ref) => {
  const variants = {
    default:   "bg-primary text-primary-foreground hover:bg-primary/90",
    secondary: "bg-secondary text-secondary-foreground hover:bg-secondary/80",
    ghost:     "hover:bg-accent hover:text-accent-foreground",
    outline:   "border border-border bg-transparent hover:bg-accent hover:text-accent-foreground",
    destructive: "bg-destructive text-destructive-foreground hover:bg-destructive/90",
    link:      "text-primary underline-offset-4 hover:underline",
  }
  const sizes = {
    default: "h-9 px-4 py-2 text-sm",
    sm:      "h-7 px-3 text-xs rounded-md",
    lg:      "h-11 px-8 text-base",
    icon:    "h-9 w-9",
  }
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md font-medium ring-offset-background transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
        "disabled:pointer-events-none disabled:opacity-50",
        variants[variant],
        sizes[size],
        className
      )}
      ref={ref}
      {...props}
    />
  )
})
Button.displayName = "Button"

export { Button }
