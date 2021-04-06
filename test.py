from modules.report import Report

data = {

    '192.168.0.1': {

        22: {

            'exploit': 'EternalBlue',
            'userlevel': 'root',
            'output': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec porttitor auctor tellus, eget molestie eros dapibus nec. Sed accumsan diam tristique mauris blandit vestibulum. Aenean ac maximus ipsum. Vestibulum tempus ultrices consectetur. Nulla egestas, ante ac molestie fringilla, libero urna convallis tellus, quis commodo est tortor sit amet mauris. Cras tristique dolor sem, sit amet lobortis metus ullamcorper ut. Donec eu turpis neque. Integer a ornare dui. Morbi tincidunt elit a dui commodo auctor. Maecenas egestas turpis in aliquet volutpat. Nulla tempus tempor metus, ut commodo velit. Proin sit amet nibh magna. Maecenas nec tincidunt neque, eget ornare turpis. Nam id risus sapien. Curabitur in ipsum dui. Integer vel nulla at felis sollicitudin malesuada.'

        },

        33: {

            'exploit': 'BlueKeep',
            'userlevel': 'root',
            'output': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec porttitor auctor tellus, eget molestie eros dapibus nec. Sed accumsan diam tristique mauris blandit vestibulum. Aenean ac maximus ipsum. Vestibulum tempus ultrices consectetur. Nulla egestas, ante ac molestie fringilla, libero urna convallis tellus, quis commodo est tortor sit amet mauris. Cras tristique dolor sem, sit amet lobortis metus ullamcorper ut. Donec eu turpis neque. Integer a ornare dui. Morbi tincidunt elit a dui commodo auctor. Maecenas egestas turpis in aliquet volutpat. Nulla tempus tempor metus, ut commodo velit. Proin sit amet nibh magna. Maecenas nec tincidunt neque, eget ornare turpis. Nam id risus sapien. Curabitur in ipsum dui. Integer vel nulla at felis sollicitudin malesuada.'


        },

        44: {

            'exploit': None,
            'userlevel': None,
            'output': None

        }

    },
    '192.168.0.2': {

        55: {

            'exploit': 'EternalBlue',
            'userlevel': 'root',
            'output': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec porttitor auctor tellus, eget molestie eros dapibus nec. Sed accumsan diam tristique mauris blandit vestibulum. Aenean ac maximus ipsum. Vestibulum tempus ultrices consectetur. Nulla egestas, ante ac molestie fringilla, libero urna convallis tellus, quis commodo est tortor sit amet mauris. Cras tristique dolor sem, sit amet lobortis metus ullamcorper ut. Donec eu turpis neque. Integer a ornare dui. Morbi tincidunt elit a dui commodo auctor. Maecenas egestas turpis in aliquet volutpat. Nulla tempus tempor metus, ut commodo velit. Proin sit amet nibh magna. Maecenas nec tincidunt neque, eget ornare turpis. Nam id risus sapien. Curabitur in ipsum dui. Integer vel nulla at felis sollicitudin malesuada.'

        },

        66: {

            'exploit': 'BlueKeep',
            'userlevel': 'root',
            'output': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec porttitor auctor tellus, eget molestie eros dapibus nec. Sed accumsan diam tristique mauris blandit vestibulum. Aenean ac maximus ipsum. Vestibulum tempus ultrices consectetur. Nulla egestas, ante ac molestie fringilla, libero urna convallis tellus, quis commodo est tortor sit amet mauris. Cras tristique dolor sem, sit amet lobortis metus ullamcorper ut. Donec eu turpis neque. Integer a ornare dui. Morbi tincidunt elit a dui commodo auctor. Maecenas egestas turpis in aliquet volutpat. Nulla tempus tempor metus, ut commodo velit. Proin sit amet nibh magna. Maecenas nec tincidunt neque, eget ornare turpis. Nam id risus sapien. Curabitur in ipsum dui. Integer vel nulla at felis sollicitudin malesuada.'

        },

        77: {

            'exploit': None,
            'userlevel': None,
            'output': None

        }

    },
    '192.168.0.3': {

        101: {

            'exploit': 'EternalBlue',
            'userlevel': 'root',
            'output': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec porttitor auctor tellus, eget molestie eros dapibus nec. Sed accumsan diam tristique mauris blandit vestibulum. Aenean ac maximus ipsum. Vestibulum tempus ultrices consectetur. Nulla egestas, ante ac molestie fringilla, libero urna convallis tellus, quis commodo est tortor sit amet mauris. Cras tristique dolor sem, sit amet lobortis metus ullamcorper ut. Donec eu turpis neque. Integer a ornare dui. Morbi tincidunt elit a dui commodo auctor. Maecenas egestas turpis in aliquet volutpat. Nulla tempus tempor metus, ut commodo velit. Proin sit amet nibh magna. Maecenas nec tincidunt neque, eget ornare turpis. Nam id risus sapien. Curabitur in ipsum dui. Integer vel nulla at felis sollicitudin malesuada.'

        },

        243: {

            'exploit': 'BlueKeep',
            'userlevel': 'root',
            'output': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec porttitor auctor tellus, eget molestie eros dapibus nec. Sed accumsan diam tristique mauris blandit vestibulum. Aenean ac maximus ipsum. Vestibulum tempus ultrices consectetur. Nulla egestas, ante ac molestie fringilla, libero urna convallis tellus, quis commodo est tortor sit amet mauris. Cras tristique dolor sem, sit amet lobortis metus ullamcorper ut. Donec eu turpis neque. Integer a ornare dui. Morbi tincidunt elit a dui commodo auctor. Maecenas egestas turpis in aliquet volutpat. Nulla tempus tempor metus, ut commodo velit. Proin sit amet nibh magna. Maecenas nec tincidunt neque, eget ornare turpis. Nam id risus sapien. Curabitur in ipsum dui. Integer vel nulla at felis sollicitudin malesuada.'

        },

        39: {

            'exploit': None,
            'userlevel': None,
            'output': None

        }

    },
    '192.168.0.2': {

        403: {

            'exploit': 'EternalBlue',
            'userlevel': 'root',
            'output': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec porttitor auctor tellus, eget molestie eros dapibus nec. Sed accumsan diam tristique mauris blandit vestibulum. Aenean ac maximus ipsum. Vestibulum tempus ultrices consectetur. Nulla egestas, ante ac molestie fringilla, libero urna convallis tellus, quis commodo est tortor sit amet mauris. Cras tristique dolor sem, sit amet lobortis metus ullamcorper ut. Donec eu turpis neque. Integer a ornare dui. Morbi tincidunt elit a dui commodo auctor. Maecenas egestas turpis in aliquet volutpat. Nulla tempus tempor metus, ut commodo velit. Proin sit amet nibh magna. Maecenas nec tincidunt neque, eget ornare turpis. Nam id risus sapien. Curabitur in ipsum dui. Integer vel nulla at felis sollicitudin malesuada.'

        },

        102: {

            'exploit': 'BlueKeep',
            'userlevel': 'root',
            'output': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec porttitor auctor tellus, eget molestie eros dapibus nec. Sed accumsan diam tristique mauris blandit vestibulum. Aenean ac maximus ipsum. Vestibulum tempus ultrices consectetur. Nulla egestas, ante ac molestie fringilla, libero urna convallis tellus, quis commodo est tortor sit amet mauris. Cras tristique dolor sem, sit amet lobortis metus ullamcorper ut. Donec eu turpis neque. Integer a ornare dui. Morbi tincidunt elit a dui commodo auctor. Maecenas egestas turpis in aliquet volutpat. Nulla tempus tempor metus, ut commodo velit. Proin sit amet nibh magna. Maecenas nec tincidunt neque, eget ornare turpis. Nam id risus sapien. Curabitur in ipsum dui. Integer vel nulla at felis sollicitudin malesuada.'

        },

        575: {

            'exploit': None,
            'userlevel': None,
            'output': None

        }

    }


}

new = Report(data)
new.generate_report()