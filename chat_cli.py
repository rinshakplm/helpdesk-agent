"""Try the agent in the terminal. Usage: python chat_cli.py [EMPLOYEE_ID]"""
import sys

from app import db
from app.agent import Agent


def main():
    db.init_db()
    emp = sys.argv[1] if len(sys.argv) > 1 else "EMP001"
    user = db.get_user(emp)
    if not user:
        print(f"No such user: {emp}")
        return
    agent = Agent()
    print(f"Signed in as {user['name']} ({user['role']}). Type 'quit' to exit.\n")
    history = []
    while True:
        try:
            text = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if text.lower() in {"quit", "exit"}:
            break
        if not text:
            continue
        out = agent.respond(user, history, text)
        print(f"\nAssistant: {out['reply']}\n")
        if out["sources"]:
            print("  Sources:", ", ".join(sorted({s["doc_id"] for s in out["sources"]})))
        for a in out["actions"]:
            print(f"  Action: {a['action']} -> {a['verdict']} ({a['rule']})")
        if out["error"]:
            print(f"  (technical detail: {out['error']})")
        print(f"  [{out['latency_ms']} ms]\n")
        history += [{"role": "user", "content": text}, {"role": "assistant", "content": out["reply"]}]


if __name__ == "__main__":
    main()
