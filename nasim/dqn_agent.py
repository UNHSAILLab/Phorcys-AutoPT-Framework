import nasim, keyboard
from nasim.agents.dqn_agent import DQNAgent

env = nasim.load("tiny.yaml")
TOTAL_STEPS = 1111
dqn_agent = DQNAgent(env, training_steps=TOTAL_STEPS)

# dqn_agent.training_steps = TOTAL_STEPS

dqn_agent.train()

print("Done")
# print("Total reward =", total_ret)
env.render_network_graph(show=True)

env.reset()
total_ret = 0
total_steps = 0
goals = 0
for i in range(TOTAL_STEPS):
    ret, steps, goal = dqn_agent.run_eval_episode(env)
    print(f"Episode {i} return={ret}, steps={steps}, goal reached={goal}")
    total_ret += ret
    total_steps += steps
    goals += int(goal)

print(f"\n{'-'*60}\nDone\n{'-'*60}")
print(f"Average Return = {total_ret / TOTAL_STEPS:.2f}")
print(f"Average Steps = {total_steps / TOTAL_STEPS:.2f}")
print(f"Goals = {goals} / {TOTAL_STEPS}")