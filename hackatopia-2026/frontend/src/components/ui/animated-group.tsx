import React, { type ReactNode } from "react";
import { motion, useReducedMotion, type Variants } from "motion/react";
import { cn } from "@/lib/utils";

type AnimatedGroupProps = {
  children: ReactNode;
  className?: string;
  variants?: { container?: Variants; item?: Variants };
};

const defaultContainer: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.1 } },
};
const defaultItem: Variants = { hidden: { opacity: 0 }, visible: { opacity: 1 } };

/** Staggers its children in on mount; shown immediately when the user prefers reduced motion. */
export function AnimatedGroup({ children, className, variants }: AnimatedGroupProps) {
  const reduce = useReducedMotion();
  return (
    <motion.div initial={reduce ? false : "hidden"} animate="visible" variants={variants?.container ?? defaultContainer} className={cn(className)}>
      {React.Children.map(children, (child, index) => (
        <motion.div key={index} variants={variants?.item ?? defaultItem}>{child}</motion.div>
      ))}
    </motion.div>
  );
}
