def assert_images_equal(image_1: str, image_2: str):
    with open(image_1, "rb") as f:
        img1 = f.read()

    with open(image_2, "rb") as f:
        img2 = f.read()

    # TODO: There are probably going to be system-to-system
    # variations, so we should probably relax this a bit -
    # i.e. compute a metric over the image and assert that they
    # are sufficiently close.
    assert img1 == img2
