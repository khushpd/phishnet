// Simple cn utility (clsx + tailwind-merge replacement)
export function cn(...classes) {
  return classes.filter(Boolean).join(" ");
}
