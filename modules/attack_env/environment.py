# https://towardsdatascience.com/creating-a-custom-openai-gym-environment-for-stock-trading-be532be3910e
import gym, logging
import numpy as np
from gym import spaces

class Environment(gym.Env):
    """ Custom Environment for Gym Interface """

    def __init__(self, nettacker_json):
        super(Environment, self).__init__()   

        log_fmt = "[%(levelname)s] [%(asctime)-15s] %(message)s"
        logging.basicConfig(filename='phorcys.log', format=log_fmt, level=logging.DEBUG)

        self.logger = logging.getLogger('Phorcys')

        self.logger.debug(f"JSON FROM Nettacker: {nettacker_json}")

        # create all actions

        # now that we have nettacker_json 
        # create the state space as the observation
        
        # Define action and observation space
        # They must be gym.spaces objects  
        
    
        # Example when using discrete actions:
        self.action_space = spaces.Discrete(10)    
        
        # Full state space for observation.
        self.observation_space = spaces.Box(low=0, high=255, shape=
                    (10, 20, 2), dtype=np.uint8)
    
    def step(self, action):
        return None
    
    def reset(self):
        return None


    def render(self):
        return None