"""
Launcher for Universal Exports application


"""

import traceback

from universal_exports import app

if __name__ == '__main__':

    # pylint: disable=W0703
    try:
        app.run(debug=app.debug, host='localhost', port=24007)
    except Exception as err:
        traceback.print_exc()
