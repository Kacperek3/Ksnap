"""REST API of the Ksnap panel and the static host of its frontend.

Run it with:   python3 src/app.py
"""

from flask import Flask, jsonify, request, send_from_directory

import config
import engine
import logbook as logbook_module
import processes
import snapshot as snapshot_module


def _error(message, status):
    return jsonify({"error": str(message)}), status


def create_app():
    app = Flask(
        __name__,
        static_folder=str(config.FRONTEND_DIR),
        static_url_path="/static",
    )

    @app.errorhandler(processes.ProcessError)
    @app.errorhandler(ValueError)
    def _bad_request(error):
        return _error(error, 400)

    @app.errorhandler(engine.EngineError)
    def _conflict(error):
        return _error(error, 409)

    @app.errorhandler(FileNotFoundError)
    def _not_found(error):
        return _error("snapshot not found", 404)

    @app.get("/")
    def index():
        return send_from_directory(config.FRONTEND_DIR, "index.html")

    @app.get("/api/status")
    def status():
        state = config.describe()
        state["restore"] = engine.session()
        return jsonify(state)

    @app.get("/api/processes")
    def list_processes():
        return jsonify(
            {"processes": processes.list_processes(request.args.get("query"))}
        )

    @app.get("/api/snapshots")
    def list_snapshots():
        return jsonify(
            {
                "snapshots": snapshot_module.list_snapshots(config.SNAPSHOT_DIR),
                "directory": str(config.SNAPSHOT_DIR),
            }
        )

    @app.delete("/api/snapshots/<name>")
    def delete_snapshot(name):
        snapshot_module.delete(config.SNAPSHOT_DIR, name)
        engine.logbook.append("Snapshot %s deleted" % name, source="api")
        return jsonify({"deleted": name})

    @app.post("/api/dump")
    def dump():
        payload = request.get_json(silent=True) or {}
        pid = processes.validate_pid(payload.get("pid"))
        name = payload.get("name") or "pid-%d.ksnap" % pid
        return jsonify({"snapshot": engine.dump(pid, name)})

    @app.post("/api/restore")
    def restore():
        payload = request.get_json(silent=True) or {}
        name = payload.get("name")
        if not name:
            raise ValueError("snapshot name is required")
        return jsonify({"restore": engine.restore(name)})

    @app.post("/api/restore/stop")
    def stop_restore():
        return jsonify({"restore": engine.stop()})

    @app.get("/api/logs")
    def logs():
        try:
            since = int(request.args.get("since", 0))
        except ValueError:
            raise ValueError("'since' must be a number")

        entries, cursor = engine.logbook.since(since)
        return jsonify({"entries": entries, "cursor": cursor})

    @app.delete("/api/logs")
    def clear_logs():
        engine.logbook.clear()
        return jsonify({"cleared": True})

    return app


if __name__ == "__main__":
    application = create_app()
    engine.logbook.append(
        "Ksnap panel started on http://%s:%d" % (config.HOST, config.PORT),
        level=logbook_module.SUCCESS,
    )
    application.run(host=config.HOST, port=config.PORT, threaded=True)
