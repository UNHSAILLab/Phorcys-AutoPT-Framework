import gym, os
import tensorflow as tf

import ray
from modules.attack_env import Environment
from ray.rllib import agents
from ray.tune.registry import register_env
# get rid of irrelevant message
tf.get_logger().setLevel('ERROR')
ray.init()

env = Environment("xyz", verbose=0)

register_env('phorcys', lambda c: env)

trainer = agents.a3c.A2CTrainer(env='phorcys')

trainer.train()

# env = make_vec_env(lambda: env, n_envs=1)

# env = make_vec_env(env, n_envs=1)

# check_env(env)
# model = A2C('CnnPolicy', env, verbose=1)
# model.learn(total_timesteps=25000)


# observation space CANNOT be a dict thus it is flattened.
# will need to do same for action space


# A2C


# env = FlattenObservation(FilterObservation(env, OBS_KEYS))



# model = A2C('MlpPolicy', env, verbose=1)

# print(env.observation_space.sample())

# ater on for proper validation
# check_env(env)


    def __init__(self):

        # Defines The Observation Space As A Ordered Dict
        self.obvSpace: OrderedDict = OrderedDict()

        # Iterate Through Each State In The State Space
        for stateSpace in self.stateSpaces:

            # Describe The Observation State For Each Host
            hostAddress = stateSpace.decodeHostAddress()
            self.obvSpace[hostAddress] = spaces.Dict({
                'accessLevel'     : spaces.MultiBinary([1,3]),
                'hostAddress'     : spaces.MultiBinary([1,4]),
                'openPorts'       : spaces.MultiBinary([1, 16]),
                'services'        : spaces.MultiBinary([1, 4]),
                'vulnerabilities' : spaces.MultiBinary([1, 10])
            })

        # Initialize The Gym Space
        gym.Space.__init__(self, None, None)

        # Generates The Initial Observation State
        self._initialObvState = self._generateInitialObvState()

    # Function that generates the initial observation state
    # @return {OrderedDict} The initial observation state
    def _generateInitialObvState(self) -> OrderedDict:

        # Defines An Ordered Dict For Holding Each State
        _initialObvState: OrderedDict = OrderedDict()

        # Adds The Parsed State
        for stateSpace in self.stateSpaces:
            hostAddress = stateSpace.decodeHostAddress()
            _initialObvState = OrderedDict({
                'accessLevel'     : stateSpace.accessLevel,
                'hostAddress'     : stateSpace.hostAddress,
                'openPorts'       : stateSpace.openPorts,
                'services'        : stateSpace.services,
                'vulnerabilities' : stateSpace.vulnerabilities
            })
            break

        return _initialObvState
