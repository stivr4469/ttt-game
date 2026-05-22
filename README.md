# soc2-sandbox

A simple two-player Tic-Tac-Toe game implemented in Python.

## Features

- Two-player mode (X and O)
- Win detection (rows, columns, diagonals)
- Draw detection
- Board state display after each move
- Input validation and error handling

## Requirements

- Python 3.9+

## How to play

```bash
python game.py
```

Players take turns entering a position (1-9):

```
 1 | 2 | 3
-----------
 4 | 5 | 6
-----------
 7 | 8 | 9
```

## Project structure

```
.
├── game.py          # Main game loop
├── board.py         # Board logic and rendering
├── player.py        # Player class
├── utils.py         # Helper functions
└── tests/           # Unit tests
```

## Running tests

```bash
python -m pytest tests/
```

## License

MIT
