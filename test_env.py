import gym, os
import tensorflow as tf

# get rid of irrelevant message
tf.get_logger().setLevel('ERROR')


from stable_baselines.common.env_checker import check_env

from stable_baselines.common.vec_env import DummyVecEnv
from stable_baselines.deepq.policies import MlpPolicy
from stable_baselines import DQN


env = gym.make('attack_environment:phorcys-v0', nettacker_json="random_JSON....")

model = DQN(MlpPolicy, env, verbose=1)
# model.learn(total_timesteps=25000)

# ater on for proper validation
# check_env(env)