/**
 * lib/utils.ts — Shared utility functions
 *
 * cn() merges Tailwind classes intelligently, resolving conflicts.
 * Example: cn("px-4 py-2", condition && "bg-primary") → "px-4 py-2 bg-primary"
 */
import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
