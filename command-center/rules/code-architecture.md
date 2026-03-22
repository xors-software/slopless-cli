# Code Architecture Standards

Write code that another developer (or future AI agent) can extend without rewriting.

## Abstraction Rules

### No magic values
Every literal that controls behavior must be a named constant or config parameter.

```typescript
// BAD
if (score > 85) { ... }
const color = "#8B4513";
setTimeout(fn, 3000);

// GOOD
const PASSING_THRESHOLD = 85;
const COLORS = { primary: "#8B4513", accent: "#DAA520" } as const;
const ANIMATION_DURATION_MS = 3000;
```

### Components, not monoliths
A single file should not exceed ~300 lines. If it does, decompose:

- Extract reusable UI into components with props
- Extract game/business logic into hooks or utility modules
- Extract configuration (themes, stats, levels) into data files

```
// BAD: 800-line page.tsx with inline styles, hardcoded stats, and game logic

// GOOD:
src/app/games/sphere-brawl/
  page.tsx              # Layout, routing — imports components
  components/
    Arena.tsx           # Canvas rendering, collision detection
    ClassSelector.tsx   # Class picker with props for class data
    StatBar.tsx         # Reusable stat display
  lib/
    classes.ts          # Class definitions as typed data
    physics.ts          # Collision, movement, damage calculations
    constants.ts        # Colors, dimensions, timing, thresholds
```

### Data-driven design
Game entities, form fields, nav items, themes — anything with multiple instances should be an array/map of typed data, not duplicated JSX.

```typescript
// BAD: copy-pasting JSX for each class
<div className="class-card">Viking Berserker</div>
<div className="class-card">Forest Ranger</div>
<div className="class-card">Knight Warrior</div>

// GOOD: map over data
const CLASSES: CharacterClass[] = [
  { id: "berserker", name: "Viking Berserker", hp: 120, attack: 15, ... },
  { id: "ranger",    name: "Forest Ranger",    hp: 90,  attack: 12, ... },
  { id: "knight",    name: "Knight Warrior",   hp: 150, attack: 10, ... },
];

{CLASSES.map(cls => <ClassCard key={cls.id} character={cls} />)}
```

### Props over assumptions
Components should accept props for anything that varies. Hardcode nothing about the parent context.

```typescript
// BAD
function Arena() {
  const width = 800;  // what if mobile?
  const players = 2;  // what if we add 4-player mode?
}

// GOOD
interface ArenaProps {
  width: number;
  height: number;
  players: Player[];
  onCollision: (a: Player, b: Player) => void;
}
```

### Type everything
No `any`. Define interfaces for all data structures. Export types that other modules need.

```typescript
export interface CharacterClass {
  id: string;
  name: string;
  hp: number;
  attack: number;
  defense: number;
  special: { name: string; description: string; cooldown: number };
  color: string;
  icon: string;
}
```

## File Organization

Follow the existing project's conventions. If none exist, use:

```
feature/
  page.tsx           # Entry point — minimal, composes components
  components/        # UI components with props
  lib/               # Logic, calculations, data, types
  hooks/             # Custom React hooks (if React)
  styles/            # CSS modules or style constants
```

## When Extending Existing Code

1. Read the existing patterns FIRST — match style, naming, structure
2. Add to existing abstractions rather than creating parallel ones
3. If the existing code is poorly structured, refactor it as part of the PR (call it out in the PR body)
4. Never duplicate code that already exists in the project

## Anti-patterns to Avoid

- 500+ line single-file components
- Inline styles repeated across elements (use CSS modules or style objects)
- Copy-pasted blocks that differ by 1-2 values (use data + map)
- Business logic mixed into render functions (extract to hooks/utils)
- Unnamed numeric constants (`if (x > 42)`)
- Tightly coupled components that can't be reused
