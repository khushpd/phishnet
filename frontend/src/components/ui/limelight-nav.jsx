import { useState, useRef, useLayoutEffect, cloneElement } from "react";
import { cn } from "../../lib/utils";

export function LimelightNav({
  items = [],
  defaultActiveIndex = 0,
  onTabChange,
  className,
  limelightClassName,
  iconContainerClassName,
  iconClassName,
}) {
  const [activeIndex, setActiveIndex] = useState(defaultActiveIndex);
  const [isReady, setIsReady] = useState(false);
  const navItemRefs = useRef([]);
  const limelightRef = useRef(null);

  useLayoutEffect(() => {
    if (items.length === 0) return;

    const limelight = limelightRef.current;
    const activeItem = navItemRefs.current[activeIndex];

    if (limelight && activeItem) {
      const newLeft =
        activeItem.offsetLeft +
        activeItem.offsetWidth / 2 -
        limelight.offsetWidth / 2;
      limelight.style.left = `${newLeft}px`;

      if (!isReady) {
        setTimeout(() => setIsReady(true), 50);
      }
    }
  }, [activeIndex, isReady, items]);

  if (items.length === 0) return null;

  const handleItemClick = (index, itemOnClick) => {
    setActiveIndex(index);
    onTabChange?.(index);
    itemOnClick?.();
  };

  return (
    <nav
      className={cn(
        "relative inline-flex items-center h-14 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-sm px-1",
        className
      )}
    >
      {items.map(({ id, icon, label, badge, onClick }, index) => (
        <a
          key={id}
          ref={(el) => (navItemRefs.current[index] = el)}
          className={cn(
            "relative z-20 flex h-full cursor-pointer items-center justify-center gap-2 px-5 select-none",
            "transition-all duration-200",
            iconContainerClassName
          )}
          onClick={() => handleItemClick(index, onClick)}
          aria-label={label}
        >
          {icon &&
            cloneElement(icon, {
              className: cn(
                "w-[18px] h-[18px] transition-all duration-200 flex-shrink-0",
                activeIndex === index
                  ? "opacity-100"
                  : "opacity-40",
                icon.props.className || "",
                iconClassName || ""
              ),
            })}
          {label && (
            <span
              className={cn(
                "text-xs font-semibold transition-all duration-200 whitespace-nowrap hidden sm:inline",
                activeIndex === index
                  ? "opacity-100 text-slate-100"
                  : "opacity-40 text-slate-400"
              )}
            >
              {label}
            </span>
          )}
          {badge != null && (
            <span
              className={cn(
                "text-xs px-1.5 py-0.5 rounded-full font-bold ml-0.5 transition-all duration-200",
                activeIndex === index
                  ? "bg-cyan-500/30 text-cyan-400"
                  : "bg-slate-800 text-slate-500"
              )}
            >
              {badge}
            </span>
          )}
        </a>
      ))}

      {/* Limelight glow */}
      <div
        ref={limelightRef}
        className={cn(
          "absolute top-0 z-10 w-11 h-[4px] rounded-full",
          isReady ? "transition-[left] duration-400 ease-in-out" : "",
          limelightClassName
        )}
        style={{
          left: "-999px",
          background: "linear-gradient(90deg, #06b6d4, #22d3ee)",
          boxShadow: "0 0 12px rgba(6,182,212,0.6), 0 30px 15px rgba(6,182,212,0.15)",
        }}
      >
        {/* Spotlight cone */}
        <div
          className="absolute left-[-30%] top-[4px] w-[160%] h-12 pointer-events-none"
          style={{
            clipPath: "polygon(10% 100%, 25% 0, 75% 0, 90% 100%)",
            background:
              "linear-gradient(to bottom, rgba(6,182,212,0.2), transparent)",
          }}
        />
      </div>
    </nav>
  );
}
