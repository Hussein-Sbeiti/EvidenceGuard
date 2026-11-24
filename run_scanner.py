import multiprocessing

from app.desktop_launcher import main


if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()
