import numpy as np
import random, nasim, time

class QFunction:
    def __init__(self, num_actions):
        self.q_func = dict()
        self.num_actions = num_actions

    def __call__(self, x):
        return self.forward(x)

    def forward(self, x):
        if isinstance(x, np.ndarray):
            x = str(x.astype(np.int))
        if x not in self.q_func:
            self.q_func[x] = np.zeros(self.num_actions, dtype=np.float32)
        return self.q_func[x]

    # def forward_batch(self, x_batch):
    #     return np.asarray([self.forward(x) for x in x_batch])

    # def update_batch(self, s_batch, a_batch, delta_batch):
    #     for s, a, delta in zip(s_batch, a_batch, delta_batch):
    #         q_vals = self.forward(s)
    #         q_vals[a] += delta

    def update(self, s, a, delta):
        q_vals = self.forward(s)
        q_vals[a] += delta

    def get_action(self, x):
        return int(self.forward(x).argmax())

    def display(self):
        pprint(self.q_func)

env = nasim.load("tiny.yaml", flat_obs=True)

rewards_all_episodes = []
num_episodes = 10000
max_steps_per_episode = 100

learning_rate = 0.1
discount = 0.99

exploration_rate = 1
max_exploration_rate = 1
min_exploration_rate = 0.01
exploration_decay_rate = 0.001

num_actions = env.action_space.n
env.generate_initial_state()

epsilon = 0.05

qfunc = QFunction(num_actions)

def get_egreedy_action(self, o):
    if random.random() > epsilon:
        return qfunc.get_action(o)
    return random.randint(0, qfunc.num_actions - 1)

def optimize(s, a, next_s, r, done):
        # get q_val for state and action performed in that state
        q_vals_raw = qfunc.forward(s)
        q_val = q_vals_raw[a]

        # get target q val = max val of next state
        target_q_val = qfunc.forward(next_s).max()
        target = r + discount * (1-done) * target_q_val

        # calculate error and update
        td_error = target - q_val
        td_delta = learning_rate * td_error

        # optimize the model
        qfunc.update(s, a, td_delta)

        s_value = q_vals_raw.max()
        return td_error, s_value

# Q-learning algorithm
state = env.reset()
for episode in range(num_episodes):
    print(f"epi: {episode}")
    state = env.reset()
    state = state
    done = False

    rewards_current_episode = 0
    # initialize new episode params

    for step in range(max_steps_per_episode): 
        # Exploration-exploitation trade-off
        exploration_rate_threshold = random.uniform(0, 1)
        action = get_egreedy_action(state, epsilon)

        new_state, reward, done, info = env.step(action)

        new_state = new_state.astype(int)

        optimize(state, action, new_state, reward, done)
        # Set new state
        state = new_state
        # Add new reward      
        rewards_current_episode += reward   
        if done == True: 
            break

    # Exploration rate decay
    exploration_rate = min_exploration_rate + \
        (max_exploration_rate - min_exploration_rate) * np.exp(-exploration_decay_rate*episode)

    # Add current episode reward to total rewards list
    rewards_all_episodes.append(rewards_current_episode)


env.render_network_graph(action=True)
# Calculate and print the average reward per thousand episodes
rewards_per_thousand_episodes = np.split(np.array(rewards_all_episodes),num_episodes/1000)
count = 1000

print("********Average reward per thousand episodes********\n")
for r in rewards_per_thousand_episodes:
    print(count, ": ", str(sum(r/1000)))
    count += 1000