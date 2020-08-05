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

## Data Flow Diagram

### YAML-based system specification

The following YAML is an example specification (example taken from [this paper (PDF)](https://www.cs.cmu.edu/~mabianto/papers/07_ase.pdf)):

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

## Threat Examples

You can add the threats key to your system YAML to load existing threats for your system, for example:

```
threats:
- id: THREAT1
  name: Attacker tampers with config file
  description: An attacker is able to introduce malicious changes into the settings file
  status: Unmanaged
  base_impact: Medium
  base_exploitability: Medium
  dfd_element: DFD1
  threat_category: Tampering
```

Note that if threats are *not* linked to DFD elements, duplicate threats may be generated when you perform threat enumeration.

```
$ threatmodel --threat-generation-method STRIDE minesweeper.yaml
[*] New threats found! Saved in minesweeper.yaml.
```
