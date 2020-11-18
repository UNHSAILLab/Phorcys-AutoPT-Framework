import numpy as np
import random
# or using gym
import gym
env = gym.make("nasim:Tiny-PO-v0", flat_obs=True)

rewards_all_episodes = []
num_episodes = 10000
max_steps_per_episode = 100

learning_rate = 0.1
discount_rate = 0.99

exploration_rate = 1
max_exploration_rate = 1
min_exploration_rate = 0.01
exploration_decay_rate = 0.001



num_actions = env.action_space.n
env.generate_initial_state()
# obs_shape = env.observation_space.shape[0]
state = env.reset()
print(state)
# exit(0)
# print("Space DIMENSIONS:")
# print(f"Space DIM: {state.ndim}")
# print(f"Space Shape: {state.shape}")
# print(f"Space SIZE: {state.size}")

q_table = np.zeros([1000, num_actions])
q_table = q_table.astype(int)
state = state.astype(int)
q_table[state, 0]
# print(obs_shape)

# print("Q_TABLE DIMENSIONS:")
# print(f"Q_TABLE DIM: {q_table.ndim}")
# print(f"Q_TABLE Shape: {q_table.shape}")
# print(f"Q_TABLE SIZE: {q_table.size}")
# print(q_table[30, 0])

# Q-learning algorithm
for episode in range(num_episodes):
    state = env.reset()
    state = state.astype(int)
    done = False

    rewards_current_episode = 0
    # initialize new episode params

    for step in range(max_steps_per_episode): 
        # Exploration-exploitation trade-off
        exploration_rate_threshold = random.uniform(0, 1)
        if exploration_rate_threshold > exploration_rate:
            action = int(np.argmax(q_table[state,:]))
            print(f"Explore action: {action}")
            print(np.argmax(q_table[state,:]))
        else:
            action = env.action_space.sample()
            print(f"Else Action: {action}")


        # Take new action
        # print(action)
        # print(type(action))
        new_state, reward, done, info = env.step(action)
        new_state = new_state.astype(int)
        print(new_state)
        # Update Q-table
        q_table[state, action] = q_table[state, action] * (1 - learning_rate) + \
            learning_rate * (reward + discount_rate * np.max(q_table[new_state, :]))
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

# Calculate and print the average reward per thousand episodes
rewards_per_thousand_episodes = np.split(np.array(rewards_all_episodes),num_episodes/1000)
count = 1000

print("********Average reward per thousand episodes********\n")
for r in rewards_per_thousand_episodes:
    print(count, ": ", str(sum(r/1000)))
    count += 1000