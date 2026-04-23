import { useState, useRef, useEffect, cloneElement } from "react";
import { motion, useScroll, useMotionValueEvent } from "framer-motion";
import { Menu } from "lucide-react";
import { cn } from "../../lib/utils";

const EXPAND_SCROLL_THRESHOLD = 80;

const containerVariants = {
  expanded: {
    y: 0,
    opacity: 1,
    width: "auto",
    transition: {
      y: { type: "spring", damping: 18, stiffness: 250 },
      opacity: { duration: 0.3 },
      type: "spring",
      damping: 20,
      stiffness: 300,
      staggerChildren: 0.07,
      delayChildren: 0.15,
    },
  },
  collapsed: {
    y: 0,
    opacity: 1,
    width: "3.5rem",
    transition: {
      type: "spring",
      damping: 20,
      stiffness: 300,
      when: "afterChildren",
      staggerChildren: 0.05,
      staggerDirection: -1,
    },
  },
};

const logoVariants = {
  expanded: {
    opacity: 1,
    x: 0,
    rotate: 0,
    transition: { type: "spring", damping: 15 },
  },
  collapsed: {
    opacity: 0,
    x: -25,
    rotate: -180,
    transition: { duration: 0.3 },
  },
};

const itemVariants = {
  expanded: {
    opacity: 1,
    x: 0,
    scale: 1,
    transition: { type: "spring", damping: 15 },
  },
  collapsed: {
    opacity: 0,
    x: -20,
    scale: 0.95,
    transition: { duration: 0.2 },
  },
};

const collapsedIconVariants = {
  expanded: { opacity: 0, scale: 0.8, transition: { duration: 0.2 } },
  collapsed: {
    opacity: 1,
    scale: 1,
    transition: {
      type: "spring",
      damping: 15,
      stiffness: 300,
      delay: 0.15,
    },
  },
};

/**
 * Floating animated navigation bar.
 *
 * Props:
 * - items: [{ id, icon, label, badge? }]
 * - activeId: currently active item id
 * - onItemClick: (id) => void
 * - brandIcon: React element for the left icon
 * - rightSlot: React element for the right side (e.g. buttons)
 * - scrollContainerRef: optional ref for the scroll container (defaults to window)
 */
export function AnimatedNav({
  items = [],
  activeId,
  onItemClick,
  brandIcon,
  rightSlot,
  scrollContainerRef,
}) {
  const [isExpanded, setExpanded] = useState(true);
  const { scrollY } = useScroll(
    scrollContainerRef ? { container: scrollContainerRef } : undefined
  );
  const lastScrollY = useRef(0);
  const scrollPositionOnCollapse = useRef(0);

  useMotionValueEvent(scrollY, "change", (latest) => {
    const previous = lastScrollY.current;

    if (isExpanded && latest > previous && latest > 150) {
      setExpanded(false);
      scrollPositionOnCollapse.current = latest;
    } else if (
      !isExpanded &&
      latest < previous &&
      scrollPositionOnCollapse.current - latest > EXPAND_SCROLL_THRESHOLD
    ) {
      setExpanded(true);
    }

    lastScrollY.current = latest;
  });

  const handleNavClick = (e) => {
    if (!isExpanded) {
      e.preventDefault();
      setExpanded(true);
    }
  };

  return (
    <div className="fixed top-5 left-1/2 -translate-x-1/2 z-50">
      <motion.nav
        initial={{ y: -80, opacity: 0 }}
        animate={isExpanded ? "expanded" : "collapsed"}
        variants={containerVariants}
        whileHover={!isExpanded ? { scale: 1.1 } : {}}
        whileTap={!isExpanded ? { scale: 0.95 } : {}}
        onClick={handleNavClick}
        className={cn(
          "flex items-center overflow-hidden rounded-full border border-slate-700/60 shadow-2xl backdrop-blur-md h-14",
          !isExpanded && "cursor-pointer justify-center"
        )}
        style={{
          background: "rgba(2, 6, 23, 0.85)",
          boxShadow:
            "0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px rgba(100,116,139,0.1), inset 0 1px 0 rgba(255,255,255,0.04)",
        }}
      >
        {/* Brand icon */}
        {brandIcon && (
          <motion.div
            variants={logoVariants}
            className="flex-shrink-0 flex items-center pl-5 pr-1"
          >
            {brandIcon}
          </motion.div>
        )}

        {/* Divider */}
        <motion.div
          variants={itemVariants}
          className="w-px h-6 bg-slate-700/50 mx-1 flex-shrink-0"
        />

        {/* Nav items */}
        <motion.div
          className={cn(
            "flex items-center gap-0.5",
            !isExpanded && "pointer-events-none"
          )}
        >
          {items.map(({ id, icon, label, badge }) => {
            const isActive = activeId === id;
            return (
              <motion.button
                key={id}
                variants={itemVariants}
                onClick={(e) => {
                  e.stopPropagation();
                  onItemClick?.(id);
                }}
                className={cn(
                  "flex items-center gap-1.5 text-xs font-semibold px-3.5 py-2 rounded-full transition-colors duration-200 whitespace-nowrap",
                  isActive
                    ? "text-cyan-400 bg-cyan-500/10"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
                )}
              >
                {icon &&
                  cloneElement(icon, {
                    className: cn(
                      "w-4 h-4 flex-shrink-0 transition-colors duration-200",
                      isActive ? "text-cyan-400" : "text-slate-500",
                      icon.props.className || ""
                    ),
                  })}
                <span className="hidden sm:inline">{label}</span>
                {badge != null && (
                  <span
                    className={cn(
                      "text-[10px] px-1.5 py-0.5 rounded-full font-bold leading-none",
                      isActive
                        ? "bg-cyan-500/25 text-cyan-400"
                        : "bg-slate-800 text-slate-500"
                    )}
                  >
                    {badge}
                  </span>
                )}
              </motion.button>
            );
          })}
        </motion.div>

        {/* Right slot (e.g. action buttons) */}
        {rightSlot && (
          <>
            <motion.div
              variants={itemVariants}
              className="w-px h-6 bg-slate-700/50 mx-1 flex-shrink-0"
            />
            <motion.div
              variants={itemVariants}
              className="flex items-center gap-2 pr-4 pl-1"
            >
              {rightSlot}
            </motion.div>
          </>
        )}

        {/* Collapsed hamburger icon overlay */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <motion.div
            variants={collapsedIconVariants}
            animate={isExpanded ? "expanded" : "collapsed"}
          >
            <Menu className="w-5 h-5 text-cyan-400" />
          </motion.div>
        </div>
      </motion.nav>
    </div>
  );
}

/**
 * Small inline animated pill nav for sub-filters (e.g. Logs filter).
 */
export function AnimatedSubNav({ items = [], activeId, onItemClick }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="inline-flex items-center gap-0.5 rounded-full border border-slate-700/60 backdrop-blur-sm px-1 py-1"
      style={{
        background: "rgba(2, 6, 23, 0.7)",
      }}
    >
      {items.map(({ id, label, count }) => {
        const isActive = activeId === id;
        return (
          <motion.button
            key={id}
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            onClick={() => onItemClick?.(id)}
            className={cn(
              "text-xs font-semibold px-3.5 py-1.5 rounded-full transition-all duration-200 whitespace-nowrap",
              isActive
                ? "text-cyan-400 bg-cyan-500/10 shadow-sm"
                : "text-slate-500 hover:text-slate-300 hover:bg-slate-800/50"
            )}
          >
            {label}
            {count != null && count > 0 && (
              <span
                className={cn(
                  "ml-1.5 text-[10px] px-1.5 py-0.5 rounded-full font-bold leading-none",
                  isActive
                    ? "bg-cyan-500/25 text-cyan-400"
                    : "bg-slate-800 text-slate-500"
                )}
              >
                {count}
              </span>
            )}
          </motion.button>
        );
      })}
    </motion.div>
  );
}
