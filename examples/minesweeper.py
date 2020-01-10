from threat_modeling.data_flow import (
    Boundary,
    Dataflow,
    BidirectionalDataflow,
    Datastore,
    ExternalEntity,
    Process,
)
from threat_modeling.project import ThreatModel

# DFD inspired by https://www.cs.cmu.edu/~mabianto/papers/07_ase.pdf

tm = ThreatModel("Minesweeper")
tm.description = "Minesweeper threat model"
elements = set()
flows = set()
boundaries = []

user = ExternalEntity("user")
elements.add(user)
directx = ExternalEntity("DirectX API")
elements.add(directx)

game = Process("Game Application")
elements.add(game)

game_file = Datastore("Game File")
elements.add(game_file)
settings_file = Datastore("Settings File")
elements.add(settings_file)

for element in elements:
    tm.add_element(element)

user_to_game = Dataflow(user.identifier, game.identifier, "User Input")
flows.add(user_to_game)
graphics_rendering = Dataflow(directx.identifier, game.identifier, "Graphics Rendering")
flows.add(graphics_rendering)
game_data = BidirectionalDataflow(game_file.identifier, game.identifier, "Game Data")
flows.add(game_data)
settings = BidirectionalDataflow(settings_file.identifier, game.identifier, "Settings")
flows.add(settings)

system = Boundary(
    "System",
    [
        directx.identifier,
        game.identifier,
        game_file.identifier,
        settings_file.identifier,
    ],
)
boundaries.append(system)

for element in list(flows) + boundaries:
    tm.add_element(element)

tm.draw()
