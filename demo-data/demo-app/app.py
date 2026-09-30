from service import process_file


def post(route):

    def decorator(function):

        function._route = route

        function._method = "POST"

        return function

    return decorator


@post("/api/upload")

def handle_upload():

    return process_file("user-upload")


if __name__ == "__main__":

    handle_upload()
 