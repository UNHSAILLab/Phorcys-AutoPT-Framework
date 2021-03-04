# https://towardsdatascience.com/creating-a-custom-openai-gym-environment-for-stock-trading-be532be3910e
import gym
from gym import spaces
import numpy as np



class Environment(gym.Env):
    """ Custom Environment for Gym Interface """

    def __init__(self, nettacker_json):
        super(Environment, self).__init__()    

        print(nettacker_json)

        # create all actions

        # now that we have nettacker_json 
        # create the state space as the observation
        
        # Define action and observation space
        # They must be gym.spaces objects  
        
    
        # Example when using discrete actions:
        self.action_space = spaces.Discrete(10)    
        
        # Example for using image as input:
        self.observation_space = spaces.Box(low=0, high=255, shape=
                    (10, 20, 2), dtype=np.uint8)
    
    def step(self, action):
        return None
    
    def reset(self):
        return None


    def render(self):
        return None