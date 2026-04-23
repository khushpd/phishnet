import { motion } from "framer-motion";
import { ArrowRight } from "lucide-react";

const MotionButton = motion.button;

export const MenuVertical = ({
  menuItems = [],
  color = "#4a9eff",
  skew = 0,
  activeId = null,
  onItemClick,
}) => {
  return (
    <div className="flex w-full flex-col gap-1 px-1">
      {menuItems.map((item, index) => {
        const isActive = activeId === item.id;
        return (
          <motion.div
            key={`${item.id}-${index}`}
            className="group/nav flex items-center gap-1.5 cursor-pointer"
            initial="initial"
            whileHover="hover"
            animate={isActive ? "hover" : "initial"}
          >
            <motion.div
              variants={{
                initial: { x: "-100%", opacity: 0 },
                hover: { x: 0, opacity: 1 },
              }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              className="z-0 flex-shrink-0"
              style={{ color }}
            >
              <ArrowRight strokeWidth={2.5} className="w-4 h-4" />
            </motion.div>

            <MotionButton
              onClick={() => onItemClick?.(item.id)}
              variants={{
                initial: { x: -20, color: isActive ? color : "#888888" },
                hover: { x: 0, color, skewX: skew },
              }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              className="font-medium text-[13px] no-underline bg-transparent border-none cursor-pointer text-left flex items-center gap-2 w-full"
            >
              {item.icon && <span className="w-4 h-4 flex-shrink-0">{item.icon}</span>}
              <span className="flex-1">{item.label}</span>
              {item.count != null && item.count > 0 && (
                <span className="text-[11px] opacity-50">{item.count}</span>
              )}
              {item.dot && (
                <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: item.dot }} />
              )}
            </MotionButton>
          </motion.div>
        );
      })}
    </div>
  );
};

export default MenuVertical;
