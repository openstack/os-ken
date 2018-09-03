from os_ken.services.protocols.bgp.operator.command import Command
from os_ken.services.protocols.bgp.operator.commands.clear import ClearCmd
from os_ken.services.protocols.bgp.operator.commands.set import SetCmd
from os_ken.services.protocols.bgp.operator.commands.show import ShowCmd


class RootCmd(Command):
    subcommands = {
        'show': ShowCmd,
        'set': SetCmd,
        'clear': ClearCmd}
