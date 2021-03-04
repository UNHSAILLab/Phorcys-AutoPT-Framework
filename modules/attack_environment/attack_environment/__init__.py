from gym.envs.registration import register 

register(
    id='phorcys-v0',
    entry_point='attack_environment.envs:Environment',
) 