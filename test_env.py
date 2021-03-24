import gym, os
import tensorflow as tf

import ray
from modules.attack_env import Environment
from ray.rllib import agents
from ray.tune.registry import register_env
# get rid of irrelevant message
# tensboard --logdir=/Users/samuelzurowski/ray_results/
tf.get_logger().setLevel('ERROR')
ray.init()


env = Environment("xyz", isVerbose=False)

register_env('phorcys', lambda c: env)

agent = agents.a3c.A2CTrainer(env='phorcys')


N_ITER = 200
s = "{:3d} reward {:6.2f}/{:6.2f}/{:6.2f} len {:6.2f} saved {}"

for n in range(N_ITER):
  result = agent.train()

  if n % 100 == 0:
    checkpoint = agent.save()
    print("checkpoint saved at", checkpoint)


  print(s.format(
    n + 1,
    result["episode_reward_min"],
    result["episode_reward_mean"],
    result["episode_reward_max"],
    result["episode_len_mean"],
    checkpoint
   ))
