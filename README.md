# threat-modeling
[![CircleCI](https://circleci.com/gh/redshiftzero/threat-modeling.svg?style=svg)](https://circleci.com/gh/redshiftzero/threat-modeling)

This is a library of threat modeling tools in Python inspired by related projects like [pytm](https://github.com/izar/pytm).

Data Flow Diagrams (DFDs) can be generated using a specification of the system architecture either in Python (using the various objects from `data_flow.py`) or using YAML and the `ThreatModel.load` class method.

## Examples

### YAML-based system specification

The following YAML is an example specification:

```yaml
---
name: Minesweeper
description: Minesweeper threat model

nodes:
  - name: Settings File
    type: Datastore
    id: DFD1
  
  - name: Game File
    type: Datastore
    id: DFD2

  - name: DirectX API
    type: ExternalEntity
    id: DFD3

  - name: user
    type: ExternalEntity
    id: DFD4

  - name: Game Application
    type: Process
    id: DFD5

boundaries:
  - name: System
    members: 
      - DFD1
      - DFD2
      - DFD3
      - DFD5

dataflows:
  - name: Settings
    first_node: DFD1
    second_node: DFD5
    bidirectional: True
  
  - name: Game Data
    first_node: DFD2
    second_node: DFD5
    bidirectional: True

  - name: Graphics Rendering
    first_node: DFD3
    second_node: DFD5
  
  - name: User Input
    first_node: DFD4
    second_node: DFD5
```

You can use this as follows:

```
>>> from threat_modeling.project import ThreatModel
>>> tm = ThreatModel.load('examples/minesweeper.yaml')
>>> tm.draw('minesweeper.png')
```

This will generate the following Data Flow Diagram:

![alt text](docs/images/minesweeper.png)

### Python-based system specification

You can also use the Python API directly, though it's less concise. You can reproduce the above example with the Python API by running `examples/minesweeper.py`:

```
$ python3 examples/minesweeper.py
```

The file will be saved by default in `dfd.png` in the current working directory.
