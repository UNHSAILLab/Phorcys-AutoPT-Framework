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
# check_env(env
