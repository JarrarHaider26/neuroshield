
import { cn } from "@/lib/utils"

const loaderVariants = {
  container: "relative",
  shape:
    "size-full animate-[spin_1.5s_linear_infinite] rounded-full border-4 border-dashed border-primary",
  logo: "absolute inset-0 m-auto flex size-1/2 items-center justify-center rounded-full text-primary",
}

const Loader = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn("h-16 w-16", loaderVariants.container, className)}
    {...props}
  >
    <div className={loaderVariants.shape} />
    <div className={loaderVariants.logo}>
      <svg
        xmlns="http://www.w3.org/2000/svg"
        className="size-full animate-pulse"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    </div>
  </div>
)
Loader.displayName = "Loader"

export { Loader }
