# threat-modeling
[![CircleCI](https://circleci.com/gh/redshiftzero/threat-modeling.svg?style=svg)](https://circleci.com/gh/redshiftzero/threat-modeling)

**Note:** this is an experimental tool in the alpha stage, the API and YAML spec format may change.

This is a library of threat modeling tools in Python inspired by related projects like [pytm](https://github.com/izar/pytm). Data Flow Diagrams (DFDs) can be generated using a YAML specification of the system architecture. If you include the threats and their child-parent relationships in the YAML specification, you can also generate attack trees.

## Installation

```
pip install --editable .
```

## CLI usage

```
$ threatmodel --help
usage: threatmodel [-h] [--attack-trees] [--dfd] input

positional arguments:
  input           system specification (yaml)

optional arguments:
  -h, --help      show this help message and exit
  --attack-trees  generate attack trees
  --dfd           generate data flow diagram
```

## Data Flow Diagram Examples

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
$ threatmodel --dfd minesweeper.yaml
[*] DFD saved in dfd.png
```

This will generate the following Data Flow Diagram:

![alt text](docs/images/minesweeper.png)

### Python-based system specification

The system can be specified either in Python (using the various objects in `threat_modeling.data_flow`) or using YAML and the `ThreatModel.load` class method.
You _can_ use the Python API directly, though it's far less concise. You can reproduce the above example with the Python API by running `examples/minesweeper.py`:

```
$ python3 examples/minesweeper.py
```

The file will be saved by default in `dfd.png` in the current working directory.

## Threat Examples

You can add the threats key.