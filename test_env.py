import gym, os
import tensorflow as tf

from gym.wrappers import FilterObservation, FlattenObservation
from modules.attack_env import Environment

from stable_baselines.common.env_checker import check_env
from stable_baselines import DQN

from stable_baselines.common import make_vec_env
from stable_baselines import A2C

# get rid of irrelevant message
tf.get_logger().setLevel('ERROR')


OBS_KEYS = ['address', 'port']
ACTION_KEYS = ['action_port', 'action_exploit']


env = Environment("xyz")


# observation space CANNOT be a dict thus it is flattened.
# will need to do same for action space


# A2C


# env = FlattenObservation(FilterObservation(env, OBS_KEYS))



# model = A2C('MlpPolicy', env, verbose=1)

# print(env.observation_space.sample())

# DQN

# model = DQN(MlpPolicy, env, verbose=1)
# model.learn(total_timesteps=25000)

# ater on for proper validation
# check_env(env)